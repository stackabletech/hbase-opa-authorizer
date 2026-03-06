# OPA Policy Testing Layer — Design

## Purpose

Add a fast, intermediate test layer that validates the Rego policy logic against realistic
OPA inputs without the overhead of a full kuttl integration test setup. This augments (not
replaces) the integration tests.

## Architecture

```
Unit tests run (Surefire)
      │
      ▼
WireMockRule ServeEventListener
      │  collects (request body, response body) per serve event
      ▼
OpaFixtureWriter.flush() in TestUtils.tearDown()
      │  remap usernames, split by result, deduplicate, write JSON
      ▼
src/test/rego/fixtures/
  allowed/   ← one .json per unique allow-path input
  denied/    ← one .json per unique deny-path input
      │
      ▼  (separate Maven phase)
exec-maven-plugin runs: opa test hbase.rego hbase_test.rego --data fixtures/
      │
      ▼
Pass / Fail
```

## Components

### 1. Fixture Capture (Java)

**`OpaFixtureWriter`** — new test-only class:
- Thread-safe list accumulates `(requestBody, responseBody)` pairs via a `ServeEventListener`
  registered on `WireMockRule` in `TestUtils`
- `flush(Path fixtureDir)` called from `TestUtils.tearDown()`:
  1. Remaps `callerUgi.userName` in raw JSON via string replacement:
     - `allowedUser` → `admin/access-hbase.test-ns.svc.cluster.local@CLUSTER.LOCAL`
     - `deniedUser`  → `unknown@CLUSTER.LOCAL`
  2. Parses response body to determine `allowed/` vs `denied/` subdirectory
  3. Deduplicates — identical post-remap JSON written only once
  4. Writes files as `{index:04d}.json`

Constants in `TestUtils`:
```java
static final String OPA_REMAP_ALLOWED = "admin/access-hbase.test-ns.svc.cluster.local@CLUSTER.LOCAL";
static final String OPA_REMAP_DENIED  = "unknown@CLUSTER.LOCAL";
```

Fixtures are committed to source control. Running `mvn test` regenerates them in-place;
a `git diff` on the fixtures directory reveals any change in payload shape.

### 2. OPA Test File (static, committed)

**`src/test/rego/hbase_test.rego`**:
```rego
package hbase_test

import data.hbase

test_all_allowed_inputs if {
    every inp in data.fixtures.allowed {
        hbase.allow with input as inp
    }
}

test_all_denied_inputs if {
    every inp in data.fixtures.denied {
        not hbase.allow with input as inp
    }
}
```

### 3. Rego Policy File (generated, not committed)

**`target/generated-test-resources/rego/hbase.rego`** — generated during
`generate-test-resources` phase from the integration test source:

- Source: `/home/andrew/gitrepos/hbase-operator/tests/templates/kuttl/opa/12-rego-rules.txt.j2`
- Transformation: strip YAML ConfigMap wrapper, replace `$NAMESPACE` with `test-ns`
- Not committed (added to `.gitignore`)

This ensures the Rego logic tested here is always identical to the integration test policy.
The `OPA_REMAP_ALLOWED` principal matches the generated `groups_for_user` entry for `admins`.

### 4. Maven Setup

Three plugin executions, all test-scoped:

**Phase `generate-test-resources`** — `exec-maven-plugin`:
- Shell script strips YAML wrapper from `12-rego-rules.txt.j2` and substitutes `$NAMESPACE=test-ns`
- Output: `target/generated-test-resources/rego/hbase.rego`

**Phase `process-test-resources`** — `download-maven-plugin`:
- Downloads pinned OPA binary to `target/opa` and chmods `+x`
- Version controlled via `<opa.version>` property in `pom.xml`
- OS/arch selected via Maven profiles: `linux_amd64`, `darwin_amd64`, `darwin_arm64`

**Phase `test`** — `exec-maven-plugin` (after Surefire):
```bash
target/opa test \
  target/generated-test-resources/rego/hbase.rego \
  src/test/rego/hbase_test.rego \
  --data src/test/rego/fixtures/
```
- Skipped when `maven.test.skip=true`
- Fails the build on any OPA test failure

## What This Tests

- The JSON the Java coprocessor sends to OPA is parseable and has the expected field structure
- The Rego policy produces correct decisions (`allow`/`deny`) for those inputs
- The admin principal passes all hooks; an unknown principal fails all hooks

## Future Extension

The username mapping can be extended to a richer set of principals (developer, readonlyuser)
to exercise nuanced Rego branches (`matches_operation`, `matches_families`). This would
require either per-test-method mapping metadata or a separate `TestOpaInputCapture` class
with realistic principals.

## Files Changed

| File | Action |
|------|--------|
| `src/test/java/tech/stackable/hbase/TestUtils.java` | Add `ServeEventListener`, call `OpaFixtureWriter.flush()` |
| `src/test/java/tech/stackable/hbase/OpaFixtureWriter.java` | New class |
| `src/test/rego/hbase_test.rego` | New file (committed) |
| `src/test/rego/fixtures/` | New directory (committed, regenerated) |
| `pom.xml` | Add `download-maven-plugin`, two `exec-maven-plugin` executions, OS profiles, `opa.version` property |
| `.gitignore` | Add `target/generated-test-resources/` |
