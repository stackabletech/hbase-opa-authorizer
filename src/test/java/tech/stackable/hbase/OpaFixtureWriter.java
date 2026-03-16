package tech.stackable.hbase;

import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.Response;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Captures WireMock OPA requests during unit tests and writes them as a single {@code
 * fixtures.json} file for offline {@code opa test} validation.
 *
 * <p>Usernames are remapped so fixtures exercise real Rego policy logic:
 *
 * <ul>
 *   <li>{@code allowedUser} → admin Kerberos principal (member of "admins" group in Rego)
 *   <li>{@code deniedUser} → unknown principal (not in any Rego group)
 *   <li>{@code readonlyUser} → readonlyuser Kerberos principal (ro ACL with operation/family
 *       restrictions in Rego; exercises the {@code matches_operation} and {@code matches_families}
 *       non-null branches)
 * </ul>
 */
public class OpaFixtureWriter {

  static final String OPA_REMAP_ALLOWED =
      "admin/access-hbase.test-ns.svc.cluster.local@CLUSTER.LOCAL";
  static final String OPA_REMAP_DENIED = "unknown@CLUSTER.LOCAL";
  static final String OPA_REMAP_READONLY =
      "readonlyuser/access-hbase.test-ns.svc.cluster.local@CLUSTER.LOCAL";

  private static final Path FIXTURES_FILE = Paths.get("target/test-rego/fixtures.json");

  /** All captured (requestBody, responseBody) pairs across all test classes in this JVM run. */
  private static final List<String[]> captured = new ArrayList<>();

  /** Accumulated fixture bodies, shared across all flush() calls in one JVM run. */
  private static final List<String> allowedFixtures = new ArrayList<>();

  private static final List<String> deniedFixtures = new ArrayList<>();

  /** Deduplication sets, shared across all flush() calls in one JVM run. */
  private static final Set<String> seenAllowed = new HashSet<>();

  private static final Set<String> seenDenied = new HashSet<>();

  /** Called by the WireMock RequestListener on each request. Thread-safe. */
  public static synchronized void capture(Request request, Response response) {
    captured.add(new String[] {request.getBodyAsString(), response.getBodyAsString()});
  }

  /**
   * Remaps captured requests, deduplicates, and writes {@code src/test/rego/fixtures.json}. Called
   * from {@link TestUtils#tearDown()} at the end of each test class.
   */
  public static void flush() throws IOException {
    List<String[]> toProcess;
    synchronized (OpaFixtureWriter.class) {
      toProcess = new ArrayList<>(captured);
      captured.clear();
    }

    synchronized (OpaFixtureWriter.class) {
      for (String[] pair : toProcess) {
        String requestBody = pair[0];
        String responseBody = pair[1];

        // Only capture requests from the standard allow/deny test users defined in TestUtils.
        // Requests from other named users (e.g. Variants-specific users) and cluster-internal
        // traffic are intentionally skipped — they are not useful for Rego policy validation.
        if (!requestBody.contains("allowedUser")
            && !requestBody.contains("deniedUser")
            && !requestBody.contains("readonlyUser")) {
          continue;
        }
        String remapped =
            requestBody
                .replace("allowedUser", OPA_REMAP_ALLOWED)
                .replace("deniedUser", OPA_REMAP_DENIED)
                .replace("readonlyUser", OPA_REMAP_READONLY);

        // WireMock stubs in this test suite always return {"result": "true"} or {"result":
        // "false"}.
        boolean allowed = responseBody.contains("\"true\"");

        if (allowed) {
          if (seenAllowed.add(remapped)) {
            allowedFixtures.add(remapped);
          }
        } else {
          if (seenDenied.add(remapped)) {
            deniedFixtures.add(remapped);
          }
        }
      }

      Files.createDirectories(FIXTURES_FILE.getParent());
      Files.writeString(FIXTURES_FILE, buildFixturesJson());
    }
  }

  private static String buildFixturesJson() {
    String allowed = String.join(",", allowedFixtures);
    String denied = String.join(",", deniedFixtures);
    return "{\"fixtures\":{\"allowed\":[" + allowed + "],\"denied\":[" + denied + "]}}";
  }
}
