package tech.stackable.hbase;

import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.createTable;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.deleteTable;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import java.util.Collections;
import org.apache.hadoop.hbase.CompareOperator;
import org.apache.hadoop.hbase.Coprocessor;
import org.apache.hadoop.hbase.client.Append;
import org.apache.hadoop.hbase.client.CheckAndMutate;
import org.apache.hadoop.hbase.client.CheckAndMutateResult;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Durability;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Increment;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.RowMutations;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.coprocessor.ObserverContext;
import org.apache.hadoop.hbase.coprocessor.ObserverContextImpl;
import org.apache.hadoop.hbase.coprocessor.RegionCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.RegionServerCoprocessorEnvironment;
import org.apache.hadoop.hbase.filter.Filter;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.regionserver.HRegionServer;
import org.apache.hadoop.hbase.regionserver.RegionCoprocessorHost;
import org.apache.hadoop.hbase.regionserver.RegionServerCoprocessorHost;
import org.apache.hadoop.hbase.regionserver.ScanType;
import org.apache.hadoop.hbase.util.Bytes;
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
    wireMockRule.addMockServiceRequestListener(OpaFixtureWriter::capture);
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
    // preFlush is an internal storage engine hook; no authorization check is applied.
    getRegionController().preFlush(regionCtx(), null);
  }

  @Test
  public void testPreCompact() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().preCompact(regionCtx(), null, null, ScanType.USER_SCAN, null, null);
          return null;
        });
  }

  // --- read+write hooks (require WRITE or READ) ---

  @Test
  public void testPreAppend() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().preAppend(regionCtx(), new Append(TEST_ROW));
          return null;
        });
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

  @Test
  public void testPreCheckAndPutWithFilter() throws Exception {
    Put put = new Put(TEST_ROW);
    assertAllowedThenDenied(
        () -> {
          getRegionController().preCheckAndPut(regionCtx(), TEST_ROW, (Filter) null, put, false);
          return null;
        });
  }

  @Test
  public void testPreCheckAndPutAfterRowLockWithFilter() throws Exception {
    Put put = new Put(TEST_ROW);
    assertAllowedThenDenied(
        () -> {
          getRegionController()
              .preCheckAndPutAfterRowLock(regionCtx(), TEST_ROW, (Filter) null, put, false);
          return null;
        });
  }

  @Test
  public void testPreCheckAndDeleteWithFilter() throws Exception {
    Delete delete = new Delete(TEST_ROW);
    assertAllowedThenDenied(
        () -> {
          getRegionController()
              .preCheckAndDelete(regionCtx(), TEST_ROW, (Filter) null, delete, false);
          return null;
        });
  }

  @Test
  public void testPreCheckAndDeleteAfterRowLockWithFilter() throws Exception {
    Delete delete = new Delete(TEST_ROW);
    assertAllowedThenDenied(
        () -> {
          getRegionController()
              .preCheckAndDeleteAfterRowLock(regionCtx(), TEST_ROW, (Filter) null, delete, false);
          return null;
        });
  }

  @Test
  public void testPreCheckAndMutateWithRowMutations() throws Exception {
    RowMutations rowMutations = new RowMutations(TEST_ROW);
    rowMutations.add(new Put(TEST_ROW));
    CheckAndMutate checkAndMutate =
        CheckAndMutate.newBuilder(TEST_ROW)
            .ifNotExists(TEST_FAMILY, TEST_QUALIFIER)
            .build(rowMutations);
    CheckAndMutateResult result = new CheckAndMutateResult(true, null);
    assertAllowedThenDenied(
        () -> {
          getRegionController().preCheckAndMutate(regionCtx(), checkAndMutate, result);
          return null;
        });
  }

  @Test
  public void testPreCheckAndMutateAfterRowLockWithRowMutations() throws Exception {
    RowMutations rowMutations = new RowMutations(TEST_ROW);
    rowMutations.add(new Put(TEST_ROW));
    CheckAndMutate checkAndMutate =
        CheckAndMutate.newBuilder(TEST_ROW)
            .ifNotExists(TEST_FAMILY, TEST_QUALIFIER)
            .build(rowMutations);
    CheckAndMutateResult result = new CheckAndMutateResult(true, null);
    assertAllowedThenDenied(
        () -> {
          getRegionController().preCheckAndMutateAfterRowLock(regionCtx(), checkAndMutate, result);
          return null;
        });
  }

  // --- bulk load hooks ---

  @Test
  public void testPreBulkLoadHFile() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().preBulkLoadHFile(regionCtx(), Collections.emptyList());
          return null;
        });
  }

  @Test
  public void testPrePrepareBulkLoad() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().prePrepareBulkLoad(regionCtx());
          return null;
        });
  }

  @Test
  public void testPreCleanupBulkLoad() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getRegionController().preCleanupBulkLoad(regionCtx());
          return null;
        });
  }

  // --- OPA fixture coverage: readonlyUser principal ---
  // These tests generate fixtures for the readonlyuser Kerberos principal (which has an ACL with
  // operations and families restrictions in the Rego policy), exercising the matches_operation and
  // matches_families non-null branches that the allowedUser/deniedUser fixtures never reach.

  @Test
  public void testReadonlyUserScanAllowed() throws Exception {
    assertReadonlyUserAllowed(
        () -> {
          getRegionController().preScannerOpen(regionCtx(), new Scan());
          return null;
        });
  }

  @Test
  public void testReadonlyUserGetAllowed() throws Exception {
    assertReadonlyUserAllowed(
        () -> {
          getRegionController().preGetOp(regionCtx(), new Get(TEST_ROW), null);
          return null;
        });
  }

  @Test
  public void testReadonlyUserExistsAllowed() throws Exception {
    assertReadonlyUserAllowed(
        () -> {
          getRegionController().preExists(regionCtx(), new Get(TEST_ROW), false);
          return null;
        });
  }

  @Test
  public void testReadonlyUserPutDenied() throws Exception {
    assertReadonlyUserDenied(
        () -> {
          getRegionController()
              .prePut(regionCtx(), new Put(TEST_ROW), null, Durability.USE_DEFAULT);
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
