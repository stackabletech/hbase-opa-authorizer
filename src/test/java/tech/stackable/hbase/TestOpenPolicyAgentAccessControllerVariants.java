package tech.stackable.hbase;

import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import java.util.Optional;
import org.apache.hadoop.hbase.client.TableDescriptor;
import org.apache.hadoop.hbase.coprocessor.ObserverContextImpl;
import org.apache.hadoop.hbase.master.MasterCoprocessorHost;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.SecureTestUtil;
import org.apache.hadoop.security.AccessControlException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * Tests for non-default coprocessor configurations (dryRun, cache). Each test manages its own
 * mini-cluster lifecycle since the coprocessor config differs per test.
 */
public class TestOpenPolicyAgentAccessControllerVariants extends TestUtils {
  public static final String OPA_URL = "http://localhost:8089";

  @RegisterExtension
  WireMockExtension wireMockExtension =
      WireMockExtension.newInstance()
          .options(wireMockConfig().port(8089).extensions(new OpaFixtureCapture()))
          .configureStaticDsl(true)
          .build();

  @Test
  public void testDryRun() throws Exception {
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
    setup(OpenPolicyAgentAccessController.class, false, OPA_URL, true, false);

    User userDenied = User.createUserForTesting(conf, "cannotCreateTables", new String[0]);

    SecureTestUtil.AccessTestAction createTable =
        () -> {
          TableDescriptor td = getTableDescriptor();
          getOpaController().preCreateTable(ObserverContextImpl.createAndPrepare(CP_ENV), td, null);
          return null;
        };

    stubFor(
        post("/")
            .withRequestBody(
                matchingJsonPath("$.input.callerUgi[?(@.userName == 'cannotCreateTables')]"))
            .willReturn(ok().withBody("{\"result\": \"false\"}")));

    try {
      userDenied.runAs(createTable);
      LOG.info("Action runs as expected due to being in dryRun mode");
    } catch (AccessControlException e) {
      throw new AssertionError("AccessControlException should not have been thrown", e);
    }
  }

  @Test
  public void testUseCache() throws Exception {
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
    setup(OpenPolicyAgentAccessController.class, false, OPA_URL, false, true);

    User userDenied = User.createUserForTesting(conf, "useCacheUser", new String[0]);

    SecureTestUtil.AccessTestAction createTable =
        () -> {
          TableDescriptor td = getTableDescriptor();
          getOpaController().preCreateTable(ObserverContextImpl.createAndPrepare(CP_ENV), td, null);
          return null;
        };

    try {
      userDenied.runAs(createTable);
    } catch (AccessControlException e) {
      throw new AssertionError("AccessControlException should not have been thrown", e);
    }

    assertEquals(Optional.of(1L), getOpaController().getAclCacheSize());
  }

  // Each test starts its own mini-cluster in its body; shut it down here so that a failure in
  // setup() or in the test itself does not leave the cluster running for the next test class.
  @AfterEach
  public void shutDownMiniCluster() throws Exception {
    tearDown();
  }

  private OpenPolicyAgentAccessController getOpaController() {
    MasterCoprocessorHost masterCpHost =
        TEST_UTIL.getMiniHBaseCluster().getMaster().getMasterCoprocessorHost();
    return masterCpHost.findCoprocessor(OpenPolicyAgentAccessController.class);
  }
}
