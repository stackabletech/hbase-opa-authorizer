# OPA Policy Testing Layer — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Capture OPA HTTP request payloads from unit tests, remap usernames to Rego-compatible principals, write them as fixture JSON files, and validate them against the real Rego policy using the `opa test` CLI — giving fast policy correctness feedback without a full integration test cluster.

**Architecture:** WireMock's `RequestListener` captures every `(request, response)` pair during unit tests. After each test class, `OpaFixtureWriter.flush()` remaps `allowedUser` → admin Kerberos principal and `deniedUser` → unknown principal, deduplicates, and writes to `src/test/rego/fixtures/{allowed,denied}/`. Maven downloads a pinned OPA binary and runs `opa test` against the fixtures and a checked-in copy of the Rego rules (derived from the integration test template) in the `verify` phase.

**Tech Stack:** WireMock 3.6.0 (`RequestListener`), Jackson (already in project), `download-maven-plugin`, `exec-maven-plugin`, OPA CLI `opa test`.

---

### Task 1: `OpaFixtureWriter` class

**Files:**
- Create: `src/test/java/tech/stackable/hbase/OpaFixtureWriter.java`

**Step 1: Create the class**

```java
package tech.stackable.hbase;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.Response;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Captures WireMock OPA requests during unit tests and writes them as fixture JSON files for
 * offline {@code opa test} validation.
 *
 * <p>Usernames are remapped so fixtures exercise real Rego policy logic:
 * <ul>
 *   <li>{@code allowedUser} → admin Kerberos principal (member of "admins" group in Rego)
 *   <li>{@code deniedUser} → unknown principal (not in any Rego group)
 * </ul>
 */
public class OpaFixtureWriter {

  static final String OPA_REMAP_ALLOWED =
      "admin/access-hbase.test-ns.svc.cluster.local@CLUSTER.LOCAL";
  static final String OPA_REMAP_DENIED = "unknown@CLUSTER.LOCAL";

  private static final Path FIXTURES_BASE = Paths.get("src/test/rego/fixtures");
  private static final Path ALLOWED_DIR = FIXTURES_BASE.resolve("allowed");
  private static final Path DENIED_DIR = FIXTURES_BASE.resolve("denied");

  /** All captured (requestBody, responseBody) pairs across all test classes in this JVM run. */
  private static final List<String[]> captured = new CopyOnWriteArrayList<>();

  /** Tracks whether we have cleared old fixture files yet in this JVM run. */
  private static final AtomicBoolean clearedOnce = new AtomicBoolean(false);

  /** Sequential file counters, shared across all flush() calls in one JVM run. */
  private static final AtomicInteger allowedIdx = new AtomicInteger(0);

  private static final AtomicInteger deniedIdx = new AtomicInteger(0);

  /** Deduplication sets, shared across all flush() calls in one JVM run. */
  private static final Set<String> seenAllowed = new HashSet<>();

  private static final Set<String> seenDenied = new HashSet<>();

  /**
   * Called by the WireMock RequestListener on each request. Thread-safe.
   */
  public static void capture(Request request, Response response) {
    captured.add(new String[] {request.getBodyAsString(), response.getBodyAsString()});
  }

  /**
   * Remaps captured requests, deduplicates, and writes fixture JSON files. Called from {@link
   * TestUtils#tearDown()} at the end of each test class.
   */
  public static void flush() throws IOException {
    if (clearedOnce.compareAndSet(false, true)) {
      deleteDir(ALLOWED_DIR);
      deleteDir(DENIED_DIR);
    }
    Files.createDirectories(ALLOWED_DIR);
    Files.createDirectories(DENIED_DIR);

    List<String[]> toProcess = List.copyOf(captured);
    captured.clear();

    for (String[] pair : toProcess) {
      String requestBody = pair[0];
      String responseBody = pair[1];

      String remapped =
          requestBody
              .replace("allowedUser", OPA_REMAP_ALLOWED)
              .replace("deniedUser", OPA_REMAP_DENIED);

      boolean allowed = responseBody.contains("\"true\"");

      synchronized (OpaFixtureWriter.class) {
        if (allowed) {
          if (seenAllowed.add(remapped)) {
            Files.writeString(
                ALLOWED_DIR.resolve(String.format("%04d.json", allowedIdx.getAndIncrement())),
                remapped);
          }
        } else {
          if (seenDenied.add(remapped)) {
            Files.writeString(
                DENIED_DIR.resolve(String.format("%04d.json", deniedIdx.getAndIncrement())),
                remapped);
          }
        }
      }
    }
  }

  private static void deleteDir(Path dir) throws IOException {
    if (Files.exists(dir)) {
      try (var entries = Files.list(dir)) {
        for (Path p : entries.toList()) {
          Files.delete(p);
        }
      }
      Files.delete(dir);
    }
  }
}
```

**Step 2: Run spotless and compile**

```bash
JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 mvn spotless:apply -q compile -q
```

Expected: BUILD SUCCESS, no errors.

**Step 3: Commit**

```bash
git add src/test/java/tech/stackable/hbase/OpaFixtureWriter.java
git commit -m "Add OpaFixtureWriter for capturing WireMock OPA fixtures"
```

---

### Task 2: Wire `OpaFixtureWriter` into the test infrastructure

**Files:**
- Modify: `src/test/java/tech/stackable/hbase/TestUtils.java`
- Modify: `src/test/java/tech/stackable/hbase/TestOpenPolicyAgentAccessController.java`
- Modify: `src/test/java/tech/stackable/hbase/TestOpenPolicyAgentAccessControllerRegion.java`
- Modify: `src/test/java/tech/stackable/hbase/TestOpenPolicyAgentAccessControllerVariants.java`

**Step 1: Add `flush()` call to `TestUtils.tearDown()`**

In `TestUtils.java`, change:
```java
protected static void tearDown() throws Exception {
  TEST_UTIL.shutdownMiniCluster();
}
```
to:
```java
protected static void tearDown() throws Exception {
  OpaFixtureWriter.flush();
  TEST_UTIL.shutdownMiniCluster();
}
```

**Step 2: Register the listener in each test class**

In each of the three test classes, find the `@BeforeClass` / `setUpClass` method and add the listener registration as the FIRST line. The `WireMockRule` is a `@ClassRule`, so it is already started by the time `@BeforeClass` runs.

`TestOpenPolicyAgentAccessController.java` — `setUpClass` currently starts with:
```java
stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
setup(OpenPolicyAgentAccessController.class, false, OPA_URL);
```
Change to:
```java
wireMockRule.addMockServiceRequestListener(OpaFixtureWriter::capture);
stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
setup(OpenPolicyAgentAccessController.class, false, OPA_URL);
```

Apply the same one-line addition (`wireMockRule.addMockServiceRequestListener(OpaFixtureWriter::capture);`) as the first line of `setUpClass` in:
- `TestOpenPolicyAgentAccessControllerRegion.java`
- `TestOpenPolicyAgentAccessControllerVariants.java`

Add the import to each class that needs it:
```java
import com.github.tomakehurst.wiremock.http.RequestListener;
```
(The method reference `OpaFixtureWriter::capture` satisfies the `RequestListener` functional interface.)

**Step 3: Run spotless and the full test suite**

```bash
JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 mvn spotless:apply -q test -q 2>&1 | grep -E 'Tests run:|BUILD'
```

Expected: 87 tests, BUILD SUCCESS. Also check that fixture files were created:

```bash
ls src/test/rego/fixtures/allowed/ | head -5
ls src/test/rego/fixtures/denied/ | head -5
```

Expected: several `.json` files in each directory.

**Step 4: Inspect a fixture to verify remapping**

```bash
cat src/test/rego/fixtures/allowed/0000.json | python3 -m json.tool | grep userName
```

Expected: output contains `"admin/access-hbase.test-ns.svc.cluster.local@CLUSTER.LOCAL"`, not `"allowedUser"`.

```bash
cat src/test/rego/fixtures/denied/0000.json | python3 -m json.tool | grep userName
```

Expected: output contains `"unknown@CLUSTER.LOCAL"`, not `"deniedUser"`.

**Step 5: Commit**

```bash
git add src/test/java/tech/stackable/hbase/TestUtils.java \
        src/test/java/tech/stackable/hbase/TestOpenPolicyAgentAccessController.java \
        src/test/java/tech/stackable/hbase/TestOpenPolicyAgentAccessControllerRegion.java \
        src/test/java/tech/stackable/hbase/TestOpenPolicyAgentAccessControllerVariants.java \
        src/test/rego/fixtures/
git commit -m "Wire OpaFixtureWriter into test teardown and register WireMock listener"
```

---

### Task 3: Add Rego test files

**Files:**
- Create: `src/test/rego/hbase.rego`
- Create: `src/test/rego/hbase_test.rego`

**Step 1: Generate `hbase.rego` from the integration test template**

The integration test Rego lives at:
`/home/andrew/gitrepos/hbase-operator/tests/templates/kuttl/opa/12-rego-rules.txt.j2`

It is a YAML ConfigMap wrapping the Rego with 4-space indentation. Strip the 9-line YAML header, remove the 4-space indent, and substitute `$NAMESPACE` with `test-ns`:

```bash
tail -n +10 /home/andrew/gitrepos/hbase-operator/tests/templates/kuttl/opa/12-rego-rules.txt.j2 \
  | sed 's/^    //' \
  | sed 's/\$NAMESPACE/test-ns/g' \
  > src/test/rego/hbase.rego
```

Verify the first few lines look like valid Rego (no YAML, no leading spaces):
```bash
head -5 src/test/rego/hbase.rego
```
Expected:
```
package hbase

default allow := false
default matches_identity(identity) := false
```

Add a comment at the top of the file noting its origin. Edit `src/test/rego/hbase.rego` to prepend:
```rego
# Derived from hbase-operator/tests/templates/kuttl/opa/12-rego-rules.txt.j2
# with $NAMESPACE replaced by "test-ns". Regenerate with:
#   tail -n +10 <path>/12-rego-rules.txt.j2 | sed 's/^    //' | sed 's/\$NAMESPACE/test-ns/g'
#
```

**Step 2: Create `hbase_test.rego`**

```bash
mkdir -p src/test/rego
```

Create `src/test/rego/hbase_test.rego`:

```rego
package hbase_test

import data.hbase

# Every fixture in allowed/ must produce allow=true under the real Rego policy.
test_all_allowed_inputs if {
	every key, fixture in data.fixtures.allowed {
		hbase.allow with input as fixture.input
	}
}

# Every fixture in denied/ must produce allow=false under the real Rego policy.
test_all_denied_inputs if {
	every key, fixture in data.fixtures.denied {
		not hbase.allow with input as fixture.input
	}
}
```

**Step 3: Commit**

```bash
git add src/test/rego/hbase.rego src/test/rego/hbase_test.rego
git commit -m "Add Rego policy file and OPA test suite"
```

---

### Task 4: Maven — download OPA and run `opa test`

**Files:**
- Modify: `pom.xml`
- Modify: `.gitignore`

**Step 1: Add `opa.version` property and OS profiles to `pom.xml`**

In the `<properties>` section, add:
```xml
<opa.version>0.63.0</opa.version>
```

After the closing `</dependencies>` tag and before `<build>`, add Maven profiles for OS detection:
```xml
<profiles>
  <profile>
    <id>opa-linux-amd64</id>
    <activation>
      <os><name>Linux</name><arch>amd64</arch></os>
    </activation>
    <properties><opa.classifier>linux_amd64_static</opa.classifier></properties>
  </profile>
  <profile>
    <id>opa-mac-amd64</id>
    <activation>
      <os><name>Mac OS X</name><arch>x86_64</arch></os>
    </activation>
    <properties><opa.classifier>darwin_amd64</opa.classifier></properties>
  </profile>
  <profile>
    <id>opa-mac-arm64</id>
    <activation>
      <os><name>Mac OS X</name><arch>aarch64</arch></os>
    </activation>
    <properties><opa.classifier>darwin_arm64</opa.classifier></properties>
  </profile>
</profiles>
```

**Step 2: Add `download-maven-plugin` to `<build><plugins>`**

```xml
<plugin>
  <groupId>com.googlecode.maven-download-plugin</groupId>
  <artifactId>download-maven-plugin</artifactId>
  <version>1.8.1</version>
  <executions>
    <execution>
      <id>download-opa</id>
      <phase>process-test-resources</phase>
      <goals><goal>wget</goal></goals>
      <configuration>
        <url>https://github.com/open-policy-agent/opa/releases/download/v${opa.version}/opa_${opa.classifier}</url>
        <outputDirectory>${project.build.directory}</outputDirectory>
        <outputFileName>opa</outputFileName>
        <skipCache>false</skipCache>
      </configuration>
    </execution>
  </executions>
</plugin>
```

**Step 3: Add `exec-maven-plugin` executions to `<build><plugins>`**

```xml
<plugin>
  <groupId>org.codehaus.mojo</groupId>
  <artifactId>exec-maven-plugin</artifactId>
  <version>3.1.0</version>
  <executions>
    <execution>
      <id>chmod-opa</id>
      <phase>process-test-resources</phase>
      <goals><goal>exec</goal></goals>
      <configuration>
        <executable>chmod</executable>
        <arguments>
          <argument>+x</argument>
          <argument>${project.build.directory}/opa</argument>
        </arguments>
      </configuration>
    </execution>
    <execution>
      <id>opa-policy-test</id>
      <phase>verify</phase>
      <goals><goal>exec</goal></goals>
      <configuration>
        <executable>${project.build.directory}/opa</executable>
        <arguments>
          <argument>test</argument>
          <argument>src/test/rego/hbase.rego</argument>
          <argument>src/test/rego/hbase_test.rego</argument>
          <argument>--data</argument>
          <argument>src/test/rego/fixtures</argument>
          <argument>-v</argument>
        </arguments>
        <skip>${maven.test.skip}</skip>
      </configuration>
    </execution>
  </executions>
</plugin>
```

Note: `opa test` runs in the `verify` phase, which is AFTER the `test` phase (where Surefire generates the fixtures). Run with `mvn verify` to execute both unit tests and OPA tests.

**Step 4: Add OPA binary to `.gitignore`**

Append to `.gitignore`:
```
/target/opa
```

**Step 5: Run spotless and verify compilation**

```bash
JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 mvn spotless:apply -q compile -q
```

Expected: BUILD SUCCESS.

**Step 6: Commit**

```bash
git add pom.xml .gitignore
git commit -m "Add download-maven-plugin and exec-maven-plugin for OPA policy testing"
```

---

### Task 5: End-to-end verification

**Step 1: Run `mvn verify`**

```bash
JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 mvn verify 2>&1 | grep -E 'Tests run:|opa|PASS|FAIL|BUILD'
```

Expected output includes:
```
Tests run: 87, Failures: 0, Errors: 0, Skipped: 1
data.hbase_test.test_all_allowed_inputs: PASS (...)
data.hbase_test.test_all_denied_inputs: PASS (...)
BUILD SUCCESS
```

**Step 2: Verify fixture count is reasonable**

```bash
echo "allowed: $(ls src/test/rego/fixtures/allowed/ | wc -l)"
echo "denied:  $(ls src/test/rego/fixtures/denied/  | wc -l)"
```

Expected: at least 20 allowed fixtures and several denied fixtures (exact count will vary).

**Step 3: Commit fixtures and final state**

```bash
git add src/test/rego/fixtures/
git commit -m "Add generated OPA fixtures from unit test capture"
```

---

## Running OPA tests standalone (no Maven)

After the first `mvn test` has generated fixtures:

```bash
target/opa test src/test/rego/hbase.rego src/test/rego/hbase_test.rego \
  --data src/test/rego/fixtures -v
```

## Keeping `hbase.rego` in sync

When `12-rego-rules.txt.j2` changes in the hbase-operator repo, regenerate:

```bash
tail -n +10 /home/andrew/gitrepos/hbase-operator/tests/templates/kuttl/opa/12-rego-rules.txt.j2 \
  | sed 's/^    //' \
  | sed 's/\$NAMESPACE/test-ns/g' \
  >> /tmp/hbase_new.rego
# Prepend the comment header, review diff, then replace src/test/rego/hbase.rego
```
