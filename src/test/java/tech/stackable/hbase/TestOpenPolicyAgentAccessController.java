package tech.stackable.hbase;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.createTable;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.deleteTable;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import java.util.ArrayList;
import java.util.List;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.client.*;
import org.apache.hadoop.hbase.coprocessor.ObserverContextImpl;
import org.apache.hadoop.hbase.master.MasterCoprocessorHost;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.SecureTestUtil;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.security.AccessControlException;
import org.junit.Rule;
import org.junit.Test;

public class TestOpenPolicyAgentAccessController extends TestUtils {
  public static final String OPA_URL = "http://localhost:8089";

  @Rule public WireMockRule wireMockRule = new WireMockRule(8089);

  @Test
  public void testCreateAndPut() throws Exception {
    LOG.info("testCreateAndPut - start");

    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
    setup(OpenPolicyAgentAccessController.class, false, OPA_URL);

    HTableDescriptor htd = getHTableDescriptor();

    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});

    // put some test data
    List<Put> puts = new ArrayList<>(100);
    for (int i = 0; i < 100; i++) {
      Put p = new Put(Bytes.toBytes(i));
      p.addColumn(TEST_FAMILY, Bytes.toBytes("myCol"), Bytes.toBytes("info " + i));
      puts.add(p);
    }
    Table table = TEST_UTIL.getConnection().getTable(htd.getTableName());
    table.put(puts);

    deleteTable(TEST_UTIL, TEST_TABLE);

    tearDown();
    LOG.info("testCreateAndPut - complete");
  }

  @Test
  public void testDeniedCreate() throws Exception {
    LOG.info("testDeniedCreate - start");

    // let all set-up calls succeed
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
    setup(OpenPolicyAgentAccessController.class, false, OPA_URL);

    try {
      // re-stub so that any subsequent calls will fail
      stubFor(post("/").willReturn(ok().withBody("{\"result\": \"false\"}")));
      HTableDescriptor htd = getHTableDescriptor();
      createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});
      fail("AccessControlException should have been thrown");
    } catch (AccessControlException e) {
      LOG.info("AccessControlException as expected: [{}]", e.getMessage());
    }

    tearDown();
    LOG.info("testDeniedCreate - complete");
  }

  @Test
  public void testDeniedCreateByUser() throws Exception {
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
    setup(OpenPolicyAgentAccessController.class, false, OPA_URL);

    User userDenied = User.createUserForTesting(conf, "cannotCreateTables", new String[0]);

    SecureTestUtil.AccessTestAction createTable =
        () -> {
          HTableDescriptor htd = getHTableDescriptor();
          getOpaController()
              .preCreateTable(ObserverContextImpl.createAndPrepare(CP_ENV), htd, null);
          return null;
        };

    // re-stub so that the call fails for the given user
    stubFor(
        post("/")
            .withRequestBody(
                matchingJsonPath("$.input.callerUgi[?(@.userName == 'cannotCreateTables')]"))
            .willReturn(ok().withBody("{\"result\": \"false\"}")));

    try {
      userDenied.runAs(createTable);
      fail("AccessControlException should have been thrown");
    } catch (AccessControlException e) {
      LOG.info("AccessControlException as expected: [{}]", e.getMessage());
    }

    tearDown();
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

    // re-stub so that the call would fail for the given user in *non*-dryRun mode
    stubFor(
        post("/")
            .withRequestBody(
                matchingJsonPath("$.input.callerUgi[?(@.userName == 'cannotCreateTables')]"))
            .willReturn(ok().withBody("{\"result\": \"false\"}")));

    try {
      userDenied.runAs(createTable);
      LOG.info("Action runs as expected due to being in dryRun mode");
    } catch (AccessControlException e) {
      fail("AccessControlException should have been thrown");
    }

    tearDown();
  }

  @Test
  public void testUseCache() throws Exception {
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
    setup(OpenPolicyAgentAccessController.class, false, OPA_URL, false, true);

    User userDenied = User.createUserForTesting(conf, "useCacheUser", new String[0]);

    // create a table explicitly using the cache from the cp-processor on the master...
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
      fail("AccessControlException should have been thrown");
    }

    // ...which we can then inspect
    LOG.info("OPA cache entries: {}", getOpaController().getAclCache().entrySet());
    // we should have only a single entry for this user as subsequent calls will hit the cache
    assertEquals(1, getOpaController().getAclCache().get("useCacheUser").entrySet().size());
    tearDown();
  }

  private static HTableDescriptor getHTableDescriptor() {
    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);

    return htd;
  }

  private OpenPolicyAgentAccessController getOpaController() {
    MasterCoprocessorHost masterCpHost =
        TEST_UTIL.getMiniHBaseCluster().getMaster().getMasterCoprocessorHost();
    return masterCpHost.findCoprocessor(OpenPolicyAgentAccessController.class);
  }
}
