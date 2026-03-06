package tech.stackable.hbase;

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
 *
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

  /** Called by the WireMock RequestListener on each request. Thread-safe. */
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
