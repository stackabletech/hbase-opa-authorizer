package tech.stackable.hbase;

import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.createTable;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.deleteTable;
import static org.junit.Assert.fail;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import java.util.ArrayList;
import java.util.List;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.NamespaceDescriptor;
import org.apache.hadoop.hbase.ServerName;
import org.apache.hadoop.hbase.client.BalanceRequest;
import org.apache.hadoop.hbase.client.MasterSwitchType;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.RegionInfo;
import org.apache.hadoop.hbase.client.RegionInfoBuilder;
import org.apache.hadoop.hbase.client.SnapshotDescription;
import org.apache.hadoop.hbase.client.Table;
import org.apache.hadoop.hbase.client.TableDescriptor;
import org.apache.hadoop.hbase.coprocessor.MasterCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.ObserverContext;
import org.apache.hadoop.hbase.coprocessor.ObserverContextImpl;
import org.apache.hadoop.hbase.master.MasterCoprocessorHost;
import org.apache.hadoop.hbase.quotas.GlobalQuotaSettings;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.SecureTestUtil;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.security.AccessControlException;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

public class TestOpenPolicyAgentAccessController extends TestUtils {
  public static final String OPA_URL = "http://localhost:8089";

  @ClassRule public static WireMockRule wireMockRule = new WireMockRule(8089);

  @BeforeClass
  public static void setUpClass() throws Exception {
    wireMockRule.addMockServiceRequestListener(OpaFixtureWriter::capture);
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
    setup(OpenPolicyAgentAccessController.class, false, OPA_URL);
  }

  @Before
  public void resetStubs() {
    WireMock.reset();
    stubFor(post("/").willReturn(ok().withBody("{\"result\": \"true\"}")));
  }

  @AfterClass
  public static void tearDownClass() throws Exception {
    tearDown();
  }

  // --- helpers ---

  private ObserverContext<MasterCoprocessorEnvironment> ctx() {
    return ObserverContextImpl.createAndPrepare(CP_ENV);
  }

  private OpenPolicyAgentAccessController getOpaController() {
    MasterCoprocessorHost masterCpHost =
        TEST_UTIL.getMiniHBaseCluster().getMaster().getMasterCoprocessorHost();
    return masterCpHost.findCoprocessor(OpenPolicyAgentAccessController.class);
  }

  // --- original tests (non-standard allow/deny patterns) ---

  @Test
  public void testCreateAndPut() throws Exception {
    LOG.info("testCreateAndPut - start");

    HTableDescriptor htd = getHTableDescriptor();
    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});

    List<Put> puts = new ArrayList<>(100);
    for (int i = 0; i < 100; i++) {
      Put p = new Put(Bytes.toBytes(i));
      p.addColumn(TEST_FAMILY, Bytes.toBytes("myCol"), Bytes.toBytes("info " + i));
      puts.add(p);
    }
    Table table = TEST_UTIL.getConnection().getTable(htd.getTableName());
    table.put(puts);

    deleteTable(TEST_UTIL, TEST_TABLE);
    LOG.info("testCreateAndPut - complete");
  }

  @Test
  public void testDeniedCreate() throws Exception {
    LOG.info("testDeniedCreate - start");
    try {
      stubFor(post("/").willReturn(ok().withBody("{\"result\": \"false\"}")));
      HTableDescriptor htd = getHTableDescriptor();
      createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});
      fail("AccessControlException should have been thrown");
    } catch (AccessControlException e) {
      logOk(e);
    }
    LOG.info("testDeniedCreate - complete");
  }

  @Test
  public void testDeniedCreateByUser() throws Exception {
    User userDenied = User.createUserForTesting(conf, "cannotCreateTables", new String[0]);
    SecureTestUtil.AccessTestAction createTable =
        () -> {
          getOpaController().preCreateTable(ctx(), getHTableDescriptor(), null);
          return null;
        };
    stubFor(
        post("/")
            .withRequestBody(
                matchingJsonPath("$.input.callerUgi[?(@.userName == 'cannotCreateTables')]"))
            .willReturn(ok().withBody("{\"result\": \"false\"}")));
    try {
      userDenied.runAs(createTable);
      fail("AccessControlException should have been thrown");
    } catch (AccessControlException e) {
      logOk(e);
    }
  }

  @Test
  public void testCreateNamespace() throws Exception {
    User userCreater = User.createUserForTesting(conf, "nsCreator", new String[0]);
    User userDenied = User.createUserForTesting(conf, "nsNonCreator", new String[0]);
    SecureTestUtil.AccessTestAction createNamespace =
        () -> {
          NamespaceDescriptor nsd = NamespaceDescriptor.create("new_ns").build();
          getOpaController().preCreateNamespace(ctx(), nsd);
          return null;
        };
    try {
      userCreater.runAs(createNamespace);
    } catch (AccessControlException e) {
      throw new AssertionError("AccessControlException should not have been thrown", e);
    }
    stubFor(
        post("/")
            .withRequestBody(matchingJsonPath("$.input.callerUgi[?(@.userName == 'nsNonCreator')]"))
            .willReturn(ok().withBody("{\"result\": \"false\"}")));
    try {
      userDenied.runAs(createNamespace);
      fail("AccessControlException should have been thrown");
    } catch (AccessControlException e) {
      logOk(e);
    }
  }

  // --- namespace hooks ---

  @Test
  public void testPreDeleteNamespace() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preDeleteNamespace(ctx(), "default");
          return null;
        });
  }

  @Test
  public void testPreModifyNamespace() throws Exception {
    NamespaceDescriptor nsd = NamespaceDescriptor.create("default").build();
    assertAllowedThenDenied(
        () -> {
          getOpaController().preModifyNamespace(ctx(), nsd);
          return null;
        });
  }

  @Test
  public void testPreGetNamespaceDescriptor() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preGetNamespaceDescriptor(ctx(), "default");
          return null;
        });
  }

  // --- table DDL hooks ---

  @Test
  public void testPreDeleteTable() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preDeleteTable(ctx(), TEST_TABLE);
          return null;
        });
  }

  @Test
  public void testPreEnableTable() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preEnableTable(ctx(), TEST_TABLE);
          return null;
        });
  }

  @Test
  public void testPreDisableTable() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preDisableTable(ctx(), TEST_TABLE);
          return null;
        });
  }

  @Test
  public void testPreTruncateTable() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preTruncateTable(ctx(), TEST_TABLE);
          return null;
        });
  }

  @Test
  public void testPreModifyTable() throws Exception {
    TableDescriptor td = getHTableDescriptor();
    assertAllowedThenDenied(
        () -> {
          getOpaController().preModifyTable(ctx(), TEST_TABLE, td, td);
          return null;
        });
  }

  @Test
  public void testPreModifyColumnFamilyStoreFileTracker() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController()
              .preModifyColumnFamilyStoreFileTracker(ctx(), TEST_TABLE, TEST_FAMILY, "FILE");
          return null;
        });
  }

  // --- flush / quota hooks ---

  @Test
  public void testPreTableFlush() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preTableFlush(ctx(), TEST_TABLE);
          return null;
        });
  }

  @Test
  public void testPreSetUserQuotaTableScope() throws Exception {
    GlobalQuotaSettings quotas = null;
    assertAllowedThenDenied(
        () -> {
          getOpaController().preSetUserQuota(ctx(), "u", TEST_TABLE, quotas);
          return null;
        });
  }

  @Test
  public void testPreSetUserQuotaNamespaceScope() throws Exception {
    GlobalQuotaSettings quotas = null;
    assertAllowedThenDenied(
        () -> {
          getOpaController()
              .preSetUserQuota(ctx(), "u", NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, quotas);
          return null;
        });
  }

  // --- region assignment / snapshot / quota hooks (existing) ---

  @Test
  public void testPreMove() throws Exception {
    RegionInfo regionInfo = RegionInfoBuilder.newBuilder(TEST_TABLE).build();
    assertAllowedThenDenied(
        () -> {
          getOpaController().preMove(ctx(), regionInfo, null, null);
          return null;
        });
  }

  @Test
  public void testPreAssign() throws Exception {
    RegionInfo regionInfo = RegionInfoBuilder.newBuilder(TEST_TABLE).build();
    assertAllowedThenDenied(
        () -> {
          getOpaController().preAssign(ctx(), regionInfo);
          return null;
        });
  }

  @Test
  public void testPreUnassign() throws Exception {
    RegionInfo regionInfo = RegionInfoBuilder.newBuilder(TEST_TABLE).build();
    assertAllowedThenDenied(
        () -> {
          getOpaController().preUnassign(ctx(), regionInfo);
          return null;
        });
  }

  @Test
  public void testPreRegionOffline() throws Exception {
    RegionInfo regionInfo = RegionInfoBuilder.newBuilder(TEST_TABLE).build();
    assertAllowedThenDenied(
        () -> {
          getOpaController().preRegionOffline(ctx(), regionInfo);
          return null;
        });
  }

  @Test
  public void testPreSplitRegion() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preSplitRegion(ctx(), TEST_TABLE, null);
          return null;
        });
  }

  @Test
  public void testPreMergeRegions() throws Exception {
    RegionInfo ri = RegionInfoBuilder.newBuilder(TEST_TABLE).build();
    assertAllowedThenDenied(
        () -> {
          getOpaController().preMergeRegions(ctx(), new RegionInfo[] {ri, ri});
          return null;
        });
  }

  @Test
  public void testPreModifyTableStoreFileTracker() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preModifyTableStoreFileTracker(ctx(), TEST_TABLE, "FILE");
          return null;
        });
  }

  @Test
  public void testPreSnapshot() throws Exception {
    SnapshotDescription snap = new SnapshotDescription("snap", TEST_TABLE);
    TableDescriptor td = getHTableDescriptor();
    assertAllowedThenDenied(
        () -> {
          getOpaController().preSnapshot(ctx(), snap, td);
          return null;
        });
  }

  @Test
  public void testPreListSnapshot() throws Exception {
    SnapshotDescription snap = new SnapshotDescription("snap", TEST_TABLE);
    assertAllowedThenDenied(
        () -> {
          getOpaController().preListSnapshot(ctx(), snap);
          return null;
        });
  }

  @Test
  public void testPreCloneSnapshot() throws Exception {
    SnapshotDescription snap = new SnapshotDescription("snap", TEST_TABLE);
    TableDescriptor td = getHTableDescriptor();
    assertAllowedThenDenied(
        () -> {
          getOpaController().preCloneSnapshot(ctx(), snap, td);
          return null;
        });
  }

  @Test
  public void testPreRestoreSnapshot() throws Exception {
    SnapshotDescription snap = new SnapshotDescription("snap", TEST_TABLE);
    TableDescriptor td = getHTableDescriptor();
    assertAllowedThenDenied(
        () -> {
          getOpaController().preRestoreSnapshot(ctx(), snap, td);
          return null;
        });
  }

  @Test
  public void testPreDeleteSnapshot() throws Exception {
    SnapshotDescription snap = new SnapshotDescription("snap", TEST_TABLE);
    assertAllowedThenDenied(
        () -> {
          getOpaController().preDeleteSnapshot(ctx(), snap);
          return null;
        });
  }

  @Test
  public void testPreSetTableQuota() throws Exception {
    GlobalQuotaSettings quotas = null;
    assertAllowedThenDenied(
        () -> {
          getOpaController().preSetTableQuota(ctx(), TEST_TABLE, quotas);
          return null;
        });
  }

  @Test
  public void testPreSetNamespaceQuota() throws Exception {
    GlobalQuotaSettings quotas = null;
    assertAllowedThenDenied(
        () -> {
          getOpaController()
              .preSetNamespaceQuota(ctx(), NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, quotas);
          return null;
        });
  }

  @Test
  public void testPreGetUserPermissionsTableScope() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preGetUserPermissions(ctx(), "u", null, TEST_TABLE, null, null);
          return null;
        });
  }

  @Test
  public void testPreGetUserPermissionsNamespaceScope() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController()
              .preGetUserPermissions(
                  ctx(), "u", NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, null, null, null);
          return null;
        });
  }

  @Test
  public void testPreBalance() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preBalance(ctx(), BalanceRequest.defaultInstance());
          return null;
        });
  }

  @Test
  public void testPreBalanceSwitch() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preBalanceSwitch(ctx(), true);
          return null;
        });
  }

  @Test
  public void testPreShutdown() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preShutdown(ctx());
          return null;
        });
  }

  @Test
  public void testPreStopMaster() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preStopMaster(ctx());
          return null;
        });
  }

  @Test
  public void testPreClearDeadServers() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preClearDeadServers(ctx());
          return null;
        });
  }

  @Test
  public void testPreDecommissionRegionServers() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preDecommissionRegionServers(ctx(), List.of(), false);
          return null;
        });
  }

  @Test
  public void testPreListDecommissionedRegionServers() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preListDecommissionedRegionServers(ctx());
          return null;
        });
  }

  @Test
  public void testPreRecommissionRegionServer() throws Exception {
    ServerName serverName = ServerName.valueOf("localhost", 16010, 12345L);
    assertAllowedThenDenied(
        () -> {
          getOpaController().preRecommissionRegionServer(ctx(), serverName, List.of());
          return null;
        });
  }

  // --- procedure / lock hooks ---

  @Test
  public void testPreAbortProcedure() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preAbortProcedure(ctx(), 1L);
          return null;
        });
  }

  @Test
  public void testPreGetProcedures() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preGetProcedures(ctx());
          return null;
        });
  }

  @Test
  public void testPreGetLocks() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preGetLocks(ctx());
          return null;
        });
  }

  @Test
  public void testPreRequestLockTableScope() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preRequestLock(ctx(), null, TEST_TABLE, null, "desc");
          return null;
        });
  }

  @Test
  public void testPreRequestLockNamespaceScope() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController()
              .preRequestLock(
                  ctx(), NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, null, null, "desc");
          return null;
        });
  }

  @Test
  public void testPreRequestLockRegionScope() throws Exception {
    RegionInfo ri = RegionInfoBuilder.newBuilder(TEST_TABLE).build();
    assertAllowedThenDenied(
        () -> {
          getOpaController().preRequestLock(ctx(), null, null, new RegionInfo[] {ri}, "desc");
          return null;
        });
  }

  @Test
  public void testPreLockHeartbeat() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preLockHeartbeat(ctx(), TEST_TABLE, "desc");
          return null;
        });
  }

  @Test
  public void testPreSetSplitOrMergeEnabled() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preSetSplitOrMergeEnabled(ctx(), true, MasterSwitchType.SPLIT);
          return null;
        });
  }

  // --- quota hooks (global scope) ---

  @Test
  public void testPreSetUserQuotaGlobalScope() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preSetUserQuota(ctx(), "u", (GlobalQuotaSettings) null);
          return null;
        });
  }

  @Test
  public void testPreSetRegionServerQuota() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preSetRegionServerQuota(ctx(), "rs1", null);
          return null;
        });
  }

  // --- replication peer hooks ---

  @Test
  public void testPreAddReplicationPeer() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preAddReplicationPeer(ctx(), "peer1", null);
          return null;
        });
  }

  @Test
  public void testPreRemoveReplicationPeer() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preRemoveReplicationPeer(ctx(), "peer1");
          return null;
        });
  }

  @Test
  public void testPreEnableReplicationPeer() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preEnableReplicationPeer(ctx(), "peer1");
          return null;
        });
  }

  @Test
  public void testPreDisableReplicationPeer() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preDisableReplicationPeer(ctx(), "peer1");
          return null;
        });
  }

  @Test
  public void testPreGetReplicationPeerConfig() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preGetReplicationPeerConfig(ctx(), "peer1");
          return null;
        });
  }

  @Test
  public void testPreUpdateReplicationPeerConfig() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preUpdateReplicationPeerConfig(ctx(), "peer1", null);
          return null;
        });
  }

  @Test
  public void testPreListReplicationPeers() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preListReplicationPeers(ctx(), ".*");
          return null;
        });
  }

  // --- throttle hooks ---

  @Test
  public void testPreSwitchRpcThrottle() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preSwitchRpcThrottle(ctx(), true);
          return null;
        });
  }

  @Test
  public void testPreIsRpcThrottleEnabled() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preIsRpcThrottleEnabled(ctx());
          return null;
        });
  }

  @Test
  public void testPreSwitchExceedThrottleQuota() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preSwitchExceedThrottleQuota(ctx(), true);
          return null;
        });
  }

  // --- configuration hooks ---

  @Test
  public void testPreUpdateMasterConfiguration() throws Exception {
    assertAllowedThenDenied(
        () -> {
          getOpaController().preUpdateMasterConfiguration(ctx(), conf);
          return null;
        });
  }
}
