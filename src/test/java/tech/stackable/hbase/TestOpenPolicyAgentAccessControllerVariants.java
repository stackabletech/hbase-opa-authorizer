package tech.stackable.hbase;

import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.junit.Assert.assertEquals;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import java.util.Optional;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.coprocessor.ObserverContextImpl;
import org.apache.hadoop.hbase.master.MasterCoprocessorHost;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.SecureTestUtil;
import org.apache.hadoop.security.AccessControlException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

/**
 * Tests for non-default coprocessor configurations (dryRun, cache). Each test manages its own
 * mini-cluster lifecycle since the coprocessor config differs per test.
 */
public class TestOpenPolicyAgentAccessControllerVariants extends TestUtils {
  public static final String OPA_URL = "http://localhost:8089";

  // @Rule (not @ClassRule) because each test starts and tears down its own mini-cluster
  // (setup/tearDown are called inside the test body, not in @BeforeClass/@AfterClass).
  @Rule public WireMockRule wireMockRule = new WireMockRule(8089);

  @Before
  public void registerOpaListener() {
    wireMockRule.addMockServiceRequestListener(OpaFixtureWriter::capture);
  }

  @Test
  public void testDryRun() throws Exception {
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
    setup(OpenPolicyAgentAccessController.class, false, OPA_URL, true, false);

    User userDenied = User.createUserForTesting(conf, "cannotCreateTables", new String[0]);

    SecureTestUtil.AccessTestAction createTable =
        () -> {
          HTableDescriptor htd = getHTableDescriptor();
          getOpaController()
              .preCreateTable(ObserverContextImpl.createAndPrepare(CP_ENV), htd, null);
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

    tearDown();
  }

  @Test
  public void testUseCache() throws Exception {
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
    setup(OpenPolicyAgentAccessController.class, false, OPA_URL, false, true);

    User userDenied = User.createUserForTesting(conf, "useCacheUser", new String[0]);

    SecureTestUtil.AccessTestAction createTable =
        () -> {
          HTableDescriptor htd = getHTableDescriptor();
          getOpaController()
              .preCreateTable(ObserverContextImpl.createAndPrepare(CP_ENV), htd, null);
          return null;
        };

    try {
      userDenied.runAs(createTable);
    } catch (AccessControlException e) {
      throw new AssertionError("AccessControlException should not have been thrown", e);
    }

    assertEquals(Optional.of(1L), getOpaController().getAclCacheSize());

    tearDown();
  }

  private OpenPolicyAgentAccessController getOpaController() {
    MasterCoprocessorHost masterCpHost =
        TEST_UTIL.getMiniHBaseCluster().getMaster().getMasterCoprocessorHost();
    return masterCpHost.findCoprocessor(OpenPolicyAgentAccessController.class);
  }
}
