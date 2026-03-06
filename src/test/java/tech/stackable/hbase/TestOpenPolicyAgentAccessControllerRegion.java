package tech.stackable.hbase;

import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.createTable;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.deleteTable;
import static org.junit.Assert.fail;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.apache.hadoop.hbase.CompareOperator;
import org.apache.hadoop.hbase.Coprocessor;
import org.apache.hadoop.hbase.client.Append;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Durability;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Increment;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.coprocessor.ObserverContext;
import org.apache.hadoop.hbase.coprocessor.ObserverContextImpl;
import org.apache.hadoop.hbase.coprocessor.RegionCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.RegionServerCoprocessorEnvironment;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.regionserver.HRegionServer;
import org.apache.hadoop.hbase.regionserver.RegionCoprocessorHost;
import org.apache.hadoop.hbase.regionserver.RegionServerCoprocessorHost;
import org.apache.hadoop.hbase.regionserver.ScanType;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.SecureTestUtil;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.security.AccessControlException;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

public class TestOpenPolicyAgentAccessControllerRegion extends TestUtils {
  public static final String OPA_URL = "http://localhost:8089";

  private static final byte[] TEST_ROW = Bytes.toBytes("testRow");
  private static RegionCoprocessorEnvironment REGION_CP_ENV;
  private static RegionServerCoprocessorEnvironment RS_CP_ENV;

  @ClassRule public static WireMockRule wireMockRule = new WireMockRule(8089);

  @BeforeClass
  public static void setUpClass() throws Exception {
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
    setup(OpenPolicyAgentAccessController.class, false, OPA_URL);

    createTable(
        TEST_UTIL, TEST_UTIL.getAdmin(), getHTableDescriptor(), new byte[][] {Bytes.toBytes("s")});

    HRegion region = TEST_UTIL.getHBaseCluster().getRegions(TEST_TABLE).get(0);
    RegionCoprocessorHost rcpHost = region.getCoprocessorHost();
    OpenPolicyAgentAccessController regionController =
        rcpHost.findCoprocessor(OpenPolicyAgentAccessController.class);
    REGION_CP_ENV =
        (RegionCoprocessorEnvironment)
            rcpHost.createEnvironment(regionController, Coprocessor.PRIORITY_HIGHEST, 1, conf);

    HRegionServer rs = TEST_UTIL.getMiniHBaseCluster().getRegionServer(0);
    RegionServerCoprocessorHost rsCpHost = rs.getRegionServerCoprocessorHost();
    OpenPolicyAgentAccessController rsController =
        rsCpHost.findCoprocessor(OpenPolicyAgentAccessController.class);
    RS_CP_ENV =
        (RegionServerCoprocessorEnvironment)
            rsCpHost.createEnvironment(rsController, Coprocessor.PRIORITY_HIGHEST, 1, conf);
  }

  @Before
  public void resetStubs() {
    WireMock.reset();
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
  }

  @AfterClass
  public static void tearDownClass() throws Exception {
    deleteTable(TEST_UTIL, TEST_TABLE);
    tearDown();
  }

  // --- helpers ---

  private ObserverContext<RegionCoprocessorEnvironment> regionCtx() {
    return ObserverContextImpl.createAndPrepare(REGION_CP_ENV);
  }

  private ObserverContext<RegionServerCoprocessorEnvironment> rsCtx() {
    return ObserverContextImpl.createAndPrepare(RS_CP_ENV);
  }

  private OpenPolicyAgentAccessController getRegionController() {
    HRegion region = TEST_UTIL.getHBaseCluster().getRegions(TEST_TABLE).get(0);
    return region.getCoprocessorHost().findCoprocessor(OpenPolicyAgentAccessController.class);
  }

  /** Stubs a deny for writeOnlyUser when action is READ, to verify READ is required. */
  private void stubDenyReadForWriteOnlyUser() {
    stubFor(
        post("/")
            .withRequestBody(
                WireMock.matchingJsonPath("$.input.callerUgi[?(@.userName == 'writeOnlyUser')]"))
            .withRequestBody(WireMock.matchingJsonPath("$.input[?(@.action == 'READ')]"))
            .willReturn(ok().withBody("{\"result\": \"false\"}")));
  }

  // --- read hooks ---

  @Test
  public void testPreGetOp() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().preGetOp(regionCtx(), new Get(TEST_ROW), null);
          return null;
        });
  }

  @Test
  public void testPreExists() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().preExists(regionCtx(), new Get(TEST_ROW), false);
          return null;
        });
  }

  @Test
  public void testPreScannerOpen() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().preScannerOpen(regionCtx(), new Scan());
          return null;
        });
  }

  // --- write hooks ---

  @Test
  public void testPrePut() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController()
              .prePut(regionCtx(), new Put(TEST_ROW), null, Durability.USE_DEFAULT);
          return null;
        });
  }

  @Test
  public void testPreDelete() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController()
              .preDelete(regionCtx(), new Delete(TEST_ROW), null, Durability.USE_DEFAULT);
          return null;
        });
  }

  @Test
  public void testPreBatchMutate() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().preBatchMutate(regionCtx(), null);
          return null;
        });
  }

  @Test
  public void testPreFlush() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().preFlush(regionCtx(), null);
          return null;
        });
  }

  @Test
  public void testPreCompact() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().preCompact(regionCtx(), null, null, ScanType.USER_SCAN, null, null);
          return null;
        });
  }

  // --- read+write hooks (require both WRITE and READ) ---

  @Test
  public void testPreAppend() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().preAppend(regionCtx(), new Append(TEST_ROW));
          return null;
        });
  }

  @Test
  public void testPreAppendRequiresRead() throws Exception {
    User writeOnlyUser = User.createUserForTesting(conf, "writeOnlyUser", new String[0]);
    stubDenyReadForWriteOnlyUser();
    SecureTestUtil.AccessTestAction action =
        () -> {
          getRegionController().preAppend(regionCtx(), new Append(TEST_ROW));
          return null;
        };
    try {
      writeOnlyUser.runAs(action);
      fail("AccessControlException should have been thrown");
    } catch (AccessControlException e) {
      logOk(e);
    }
  }

  @Test
  public void testPreIncrement() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().preIncrement(regionCtx(), new Increment(TEST_ROW));
          return null;
        });
  }

  @Test
  public void testPreIncrementRequiresRead() throws Exception {
    User writeOnlyUser = User.createUserForTesting(conf, "writeOnlyUser", new String[0]);
    stubDenyReadForWriteOnlyUser();
    SecureTestUtil.AccessTestAction action =
        () -> {
          getRegionController().preIncrement(regionCtx(), new Increment(TEST_ROW));
          return null;
        };
    try {
      writeOnlyUser.runAs(action);
      fail("AccessControlException should have been thrown");
    } catch (AccessControlException e) {
      logOk(e);
    }
  }

  @Test
  public void testPreCheckAndPut() throws Exception {
    Put put = new Put(TEST_ROW);
    assertAllowedThenDenied(
        () -> {
          getRegionController()
              .preCheckAndPut(
                  regionCtx(),
                  TEST_ROW,
                  TEST_FAMILY,
                  TEST_QUALIFIER,
                  CompareOperator.EQUAL,
                  null,
                  put,
                  false);
          return null;
        });
  }

  @Test
  public void testPreCheckAndPutRequiresRead() throws Exception {
    User writeOnlyUser = User.createUserForTesting(conf, "writeOnlyUser", new String[0]);
    stubDenyReadForWriteOnlyUser();
    Put put = new Put(TEST_ROW);
    SecureTestUtil.AccessTestAction action =
        () -> {
          getRegionController()
              .preCheckAndPut(
                  regionCtx(),
                  TEST_ROW,
                  TEST_FAMILY,
                  TEST_QUALIFIER,
                  CompareOperator.EQUAL,
                  null,
                  put,
                  false);
          return null;
        };
    try {
      writeOnlyUser.runAs(action);
      fail("AccessControlException should have been thrown");
    } catch (AccessControlException e) {
      logOk(e);
    }
  }

  @Test
  public void testPreCheckAndPutAfterRowLock() throws Exception {
    Put put = new Put(TEST_ROW);
    assertAllowedThenDenied(
        () -> {
          getRegionController()
              .preCheckAndPutAfterRowLock(
                  regionCtx(),
                  TEST_ROW,
                  TEST_FAMILY,
                  TEST_QUALIFIER,
                  CompareOperator.EQUAL,
                  null,
                  put,
                  false);
          return null;
        });
  }

  @Test
  public void testPreCheckAndDelete() throws Exception {
    Delete delete = new Delete(TEST_ROW);
    assertAllowedThenDenied(
        () -> {
          getRegionController()
              .preCheckAndDelete(
                  regionCtx(),
                  TEST_ROW,
                  TEST_FAMILY,
                  TEST_QUALIFIER,
                  CompareOperator.EQUAL,
                  null,
                  delete,
                  false);
          return null;
        });
  }

  @Test
  public void testPreCheckAndDeleteAfterRowLock() throws Exception {
    Delete delete = new Delete(TEST_ROW);
    assertAllowedThenDenied(
        () -> {
          getRegionController()
              .preCheckAndDeleteAfterRowLock(
                  regionCtx(),
                  TEST_ROW,
                  TEST_FAMILY,
                  TEST_QUALIFIER,
                  CompareOperator.EQUAL,
                  null,
                  delete,
                  false);
          return null;
        });
  }

  // --- RegionServer hooks ---

  private OpenPolicyAgentAccessController getRsController() {
    HRegionServer rs = TEST_UTIL.getMiniHBaseCluster().getRegionServer(0);
    return rs.getRegionServerCoprocessorHost()
        .findCoprocessor(OpenPolicyAgentAccessController.class);
  }

  @Test
  public void testPreRollWALWriterRequest() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRsController().preRollWALWriterRequest(rsCtx());
          return null;
        });
  }

  @Test
  public void testPreReplicateLogEntries() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRsController().preReplicateLogEntries(rsCtx());
          return null;
        });
  }

  @Test
  public void testPreClearCompactionQueues() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRsController().preClearCompactionQueues(rsCtx());
          return null;
        });
  }

  @Test
  public void testPreClearRegionBlockCache() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRsController().preClearRegionBlockCache(rsCtx());
          return null;
        });
  }

  @Test
  public void testPreUpdateRegionServerConfiguration() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRsController().preUpdateRegionServerConfiguration(rsCtx(), conf);
          return null;
        });
  }

  @Test
  public void testPreStopRegionServer() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRsController().preStopRegionServer(rsCtx());
          return null;
        });
  }
}
