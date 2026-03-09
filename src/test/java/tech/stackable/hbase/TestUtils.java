package tech.stackable.hbase;

import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.apache.hadoop.hbase.AuthUtil.toGroupEntry;
import static org.apache.hadoop.hbase.security.access.SecureTestUtil.*;
import static org.junit.Assert.*;
import static tech.stackable.hbase.OpenPolicyAgentAccessController.OPA_POLICY_CACHE;
import static tech.stackable.hbase.OpenPolicyAgentAccessController.OPA_POLICY_DRYRUN;

import com.google.common.base.Strings;
import java.util.Collection;
import java.util.List;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.hbase.*;
import org.apache.hadoop.hbase.client.Connection;
import org.apache.hadoop.hbase.client.ConnectionFactory;
import org.apache.hadoop.hbase.coprocessor.CoprocessorHost;
import org.apache.hadoop.hbase.coprocessor.MasterCoprocessor;
import org.apache.hadoop.hbase.coprocessor.MasterCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.RegionCoprocessor;
import org.apache.hadoop.hbase.io.hfile.HFile;
import org.apache.hadoop.hbase.master.MasterCoprocessorHost;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.regionserver.RegionCoprocessorHost;
import org.apache.hadoop.hbase.regionserver.RegionServerCoprocessorHost;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.*;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.security.AccessControlException;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestUtils {
  protected static final Logger LOG = LoggerFactory.getLogger(TestUtils.class);
  protected static final HBaseTestingUtility TEST_UTIL = new HBaseTestingUtility();
  protected static Configuration conf;
  protected static Connection systemUserConnection;

  // we can't specify AccessController here as we have our own impl
  protected static MasterCoprocessor MASTER_ACCESS_CONTROLLER;
  protected static RegionCoprocessor REGION_ACCESS_CONTROLLER;
  protected static MasterCoprocessorEnvironment CP_ENV;

  protected static final byte[] TEST_FAMILY = Bytes.toBytes("f1");
  protected static final byte[] TEST_QUALIFIER = Bytes.toBytes("q1");
  protected static final TableName TEST_TABLE = TableName.valueOf("testtable1");

  protected static User SUPERUSER;
  protected static User USER_ADMIN;
  protected static User USER_RW;
  protected static User USER_RO;
  protected static User USER_OWNER;
  protected static User USER_CREATE;
  protected static User USER_NONE;
  protected static User USER_ADMIN_CF;

  protected static final String GROUP_ADMIN = "group_admin";
  protected static final String GROUP_CREATE = "group_create";
  protected static final String GROUP_READ = "group_read";
  protected static final String GROUP_WRITE = "group_write";

  protected static User ALLOWED_USER;
  protected static User DENIED_USER;
  protected static User READONLY_USER;

  protected static User USER_GROUP_ADMIN;
  protected static User USER_GROUP_CREATE;
  protected static User USER_GROUP_READ;
  protected static User USER_GROUP_WRITE;

  @SuppressWarnings("rawtypes")
  protected static void setup(Class accessControllerClass, boolean usesAclTable, String opaUrl)
      throws Exception {
    setup(accessControllerClass, usesAclTable, opaUrl, false, false);
  }

  @SuppressWarnings("rawtypes")
  protected static void setup(
      Class accessControllerClass,
      boolean usesAclTable,
      String opaUrl,
      boolean dryRun,
      boolean useCache)
      throws Exception {
    conf = TEST_UTIL.getConfiguration();
    conf.setBoolean(OPA_POLICY_DRYRUN, dryRun);
    conf.setBoolean(OPA_POLICY_CACHE, useCache);
    conf.setInt(HConstants.REGION_SERVER_HIGH_PRIORITY_HANDLER_COUNT, 10);

    // default is 10s which is difficult when step-through debugging
    conf.setInt(HConstants.HBASE_RPC_SHORTOPERATION_TIMEOUT_KEY, 600000);

    if (!Strings.isNullOrEmpty(opaUrl)) {
      conf.set(OpenPolicyAgentAccessController.OPA_POLICY_URL_PROP, opaUrl);
    }

    conf.set(
        CommonConfigurationKeys.HADOOP_SECURITY_GROUP_MAPPING,
        TestAccessController.MyShellBasedUnixGroupsMapping.class.getName());

    UserGroupInformation.setConfiguration(conf);

    conf.set(
        CommonConfigurationKeys.HADOOP_SECURITY_GROUP_MAPPING,
        TestAccessController.MyShellBasedUnixGroupsMapping.class.getName());

    conf.set("hadoop.security.authorization", "false");
    conf.set("hadoop.security.authentication", "simple");
    conf.set(
        CoprocessorHost.MASTER_COPROCESSOR_CONF_KEY,
        accessControllerClass.getName() + "," + MasterSyncObserver.class.getName());
    conf.set(CoprocessorHost.REGION_COPROCESSOR_CONF_KEY, accessControllerClass.getName());
    conf.set(CoprocessorHost.REGIONSERVER_COPROCESSOR_CONF_KEY, accessControllerClass.getName());

    conf.setInt(HFile.FORMAT_VERSION_KEY, 3);
    conf.set(User.HBASE_SECURITY_AUTHORIZATION_CONF_KEY, "true");
    conf.setBoolean(AccessControlConstants.EXEC_PERMISSION_CHECKS_KEY, true);
    configureSuperuser(conf);

    TEST_UTIL.startMiniCluster();
    MasterCoprocessorHost masterCpHost =
        TEST_UTIL.getMiniHBaseCluster().getMaster().getMasterCoprocessorHost();
    masterCpHost.load(accessControllerClass, Coprocessor.PRIORITY_HIGHEST, conf);
    MASTER_ACCESS_CONTROLLER = masterCpHost.findCoprocessor(accessControllerClass);

    for (int i = 0; i < TEST_UTIL.getMiniHBaseCluster().getNumLiveRegionServers(); i++) {
      RegionServerCoprocessorHost regionCpHost =
          TEST_UTIL.getMiniHBaseCluster().getRegionServer(i).getRegionServerCoprocessorHost();
      regionCpHost.load(accessControllerClass, Coprocessor.PRIORITY_HIGHEST, conf);
    }
    REGION_ACCESS_CONTROLLER =
        (RegionCoprocessor)
            TEST_UTIL
                .getMiniHBaseCluster()
                .getRegionServer(0)
                .getRegionServerCoprocessorHost()
                .findCoprocessor(accessControllerClass);

    CP_ENV =
        masterCpHost.createEnvironment(
            MASTER_ACCESS_CONTROLLER, Coprocessor.PRIORITY_HIGHEST, 1, conf);

    if (usesAclTable) {
      TEST_UTIL.waitUntilAllRegionsAssigned(PermissionStorage.ACL_TABLE_NAME);
    }

    SUPERUSER = User.createUserForTesting(conf, "admin", new String[] {"supergroup"});
    USER_ADMIN = User.createUserForTesting(conf, "admin2", new String[0]);
    USER_RW = User.createUserForTesting(conf, "rwuser", new String[0]);
    USER_RO = User.createUserForTesting(conf, "rouser", new String[0]);
    USER_OWNER = User.createUserForTesting(conf, "owner", new String[0]);
    USER_CREATE = User.createUserForTesting(conf, "tbl_create", new String[0]);
    USER_NONE = User.createUserForTesting(conf, "nouser", new String[0]);
    USER_ADMIN_CF = User.createUserForTesting(conf, "col_family_admin", new String[0]);

    USER_GROUP_ADMIN =
        User.createUserForTesting(conf, "user_group_admin", new String[] {GROUP_ADMIN});
    USER_GROUP_CREATE =
        User.createUserForTesting(conf, "user_group_create", new String[] {GROUP_CREATE});
    USER_GROUP_READ = User.createUserForTesting(conf, "user_group_read", new String[] {GROUP_READ});
    USER_GROUP_WRITE =
        User.createUserForTesting(conf, "user_group_write", new String[] {GROUP_WRITE});

    systemUserConnection = TEST_UTIL.getConnection();

    ALLOWED_USER = User.createUserForTesting(conf, "allowedUser", new String[0]);
    DENIED_USER = User.createUserForTesting(conf, "deniedUser", new String[0]);
    READONLY_USER = User.createUserForTesting(conf, "readonlyUser", new String[0]);
  }

  protected static void setUpTables() throws Exception {
    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);
    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});

    HRegion region = TEST_UTIL.getHBaseCluster().getRegions(TEST_TABLE).get(0);
    RegionCoprocessorHost rcpHost = region.getCoprocessorHost();
    rcpHost.createEnvironment(REGION_ACCESS_CONTROLLER, Coprocessor.PRIORITY_HIGHEST, 1, conf);

    // Set up initial grants

    grantGlobal(
        TEST_UTIL,
        USER_ADMIN.getShortName(),
        Permission.Action.ADMIN,
        Permission.Action.CREATE,
        Permission.Action.READ,
        Permission.Action.WRITE);

    grantOnTable(
        TEST_UTIL,
        USER_RW.getShortName(),
        TEST_TABLE,
        TEST_FAMILY,
        null,
        Permission.Action.READ,
        Permission.Action.WRITE);

    // USER_CREATE is USER_RW plus CREATE permissions
    grantOnTable(
        TEST_UTIL,
        USER_CREATE.getShortName(),
        TEST_TABLE,
        null,
        null,
        Permission.Action.CREATE,
        Permission.Action.READ,
        Permission.Action.WRITE);

    grantOnTable(
        TEST_UTIL, USER_RO.getShortName(), TEST_TABLE, TEST_FAMILY, null, Permission.Action.READ);

    grantOnTable(
        TEST_UTIL,
        USER_ADMIN_CF.getShortName(),
        TEST_TABLE,
        TEST_FAMILY,
        null,
        Permission.Action.ADMIN,
        Permission.Action.CREATE);

    grantGlobal(TEST_UTIL, toGroupEntry(GROUP_ADMIN), Permission.Action.ADMIN);
    grantGlobal(TEST_UTIL, toGroupEntry(GROUP_CREATE), Permission.Action.CREATE);
    grantGlobal(TEST_UTIL, toGroupEntry(GROUP_READ), Permission.Action.READ);
    grantGlobal(TEST_UTIL, toGroupEntry(GROUP_WRITE), Permission.Action.WRITE);

    assertEquals(5, PermissionStorage.getTablePermissions(conf, TEST_TABLE).size());
    int size = 0;
    try {
      size =
          AccessControlClient.getUserPermissions(systemUserConnection, TEST_TABLE.toString())
              .size();
    } catch (Throwable e) {
      LOG.error("error during call of AccessControlClient.getUserPermissions. ", e);
      fail("error during call of AccessControlClient.getUserPermissions.");
    }
    assertEquals(5, size);
  }

  protected static void logOk(AccessControlException e) {
    LOG.info("AccessControlException as expected: [{}]", e.getMessage());
  }

  protected void assertReadonlyUserAllowed(SecureTestUtil.AccessTestAction action)
      throws Exception {
    READONLY_USER.runAs(action);
  }

  protected void assertReadonlyUserDenied(SecureTestUtil.AccessTestAction action) throws Exception {
    stubFor(
        post("/")
            .withRequestBody(matchingJsonPath("$.input.callerUgi[?(@.userName == 'readonlyUser')]"))
            .willReturn(ok().withBody("{\"result\": \"false\"}")));
    try {
      READONLY_USER.runAs(action);
      fail("AccessControlException should have been thrown");
    } catch (AccessControlException e) {
      logOk(e);
    }
  }

  protected void assertAllowedThenDenied(SecureTestUtil.AccessTestAction action) throws Exception {
    ALLOWED_USER.runAs(action);
    stubFor(
        post("/")
            .withRequestBody(matchingJsonPath("$.input.callerUgi[?(@.userName == 'deniedUser')]"))
            .willReturn(ok().withBody("{\"result\": \"false\"}")));
    try {
      DENIED_USER.runAs(action);
      fail("AccessControlException should have been thrown");
    } catch (AccessControlException e) {
      logOk(e);
    }
  }

  protected static void tearDown() throws Exception {
    OpaFixtureWriter.flush();
    TEST_UTIL.shutdownMiniCluster();
  }

  protected static void cleanUpTables() throws Exception {
    // Clean the _acl_ table
    try {
      deleteTable(TEST_UTIL, TEST_TABLE);
    } catch (TableNotFoundException ex) {
      // Test deleted the table, no problem
      LOG.info("Test deleted table {}", TEST_TABLE);
    }
    // Verify all table/namespace permissions are erased
    assertEquals(0, PermissionStorage.getTablePermissions(conf, TEST_TABLE).size());
    assertEquals(
        0,
        PermissionStorage.getNamespacePermissions(conf, TEST_TABLE.getNamespaceAsString()).size());
  }

  protected void validateTableACLForGetUserPermissions(
      final Connection conn,
      User nSUser1,
      User tableGroupUser1,
      User tableGroupUser2,
      String nsPrefix,
      TableName table1,
      TableName table2,
      byte[] TEST_QUALIFIER2,
      Collection<String> superUsers)
      throws Throwable {
    AccessTestAction tableUserPermissionAction =
        () -> {
          try (Connection conn1 = ConnectionFactory.createConnection(conf)) {
            conn1
                .getAdmin()
                .getUserPermissions(
                    GetUserPermissionsRequest.newBuilder(TEST_TABLE)
                        .withFamily(TEST_FAMILY)
                        .withQualifier(TEST_QUALIFIER)
                        .withUserName("dummy")
                        .build());
          }
          return null;
        };
    verifyAllowed(tableUserPermissionAction, SUPERUSER, USER_ADMIN, USER_OWNER, USER_ADMIN_CF);
    verifyDenied(tableUserPermissionAction, USER_CREATE, USER_RW, USER_RO, USER_NONE, USER_CREATE);

    List<UserPermission> userPermissions;
    assertEquals(12, AccessControlClient.getUserPermissions(conn, nsPrefix + ".*").size());
    assertEquals(6, AccessControlClient.getUserPermissions(conn, table1.getNameAsString()).size());
    assertEquals(
        6,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), HConstants.EMPTY_STRING)
            .size());
    userPermissions =
        AccessControlClient.getUserPermissions(
            conn, table1.getNameAsString(), USER_ADMIN_CF.getName());
    verifyGetUserPermissionResult(userPermissions, 1, null, null, USER_ADMIN_CF.getName(), null);
    assertEquals(
        0,
        AccessControlClient.getUserPermissions(conn, table1.getNameAsString(), nSUser1.getName())
            .size());
    // Table group user ACL
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), tableGroupUser1.getName())
            .size());
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(
                conn, table2.getNameAsString(), tableGroupUser2.getName())
            .size());

    // Table Users + CF
    assertEquals(
        12,
        AccessControlClient.getUserPermissions(conn, nsPrefix + ".*", HConstants.EMPTY_BYTE_ARRAY)
            .size());
    userPermissions = AccessControlClient.getUserPermissions(conn, nsPrefix + ".*", TEST_FAMILY);
    verifyGetUserPermissionResult(userPermissions, 3, TEST_FAMILY, null, null, null);
    assertEquals(
        0,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), Bytes.toBytes("dummmyCF"))
            .size());

    // Table Users + CF + User
    assertEquals(
        3,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, HConstants.EMPTY_STRING)
            .size());
    userPermissions =
        AccessControlClient.getUserPermissions(
            conn, table1.getNameAsString(), TEST_FAMILY, USER_ADMIN_CF.getName());
    verifyGetUserPermissionResult(
        userPermissions, 1, null, null, USER_ADMIN_CF.getName(), superUsers);
    assertEquals(
        0,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, nSUser1.getName())
            .size());

    // Table Users + CF + CQ
    assertEquals(
        3,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, HConstants.EMPTY_BYTE_ARRAY)
            .size());
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, TEST_QUALIFIER)
            .size());
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, TEST_QUALIFIER2)
            .size());
    assertEquals(
        2,
        AccessControlClient.getUserPermissions(
                conn,
                table1.getNameAsString(),
                HConstants.EMPTY_BYTE_ARRAY,
                HConstants.EMPTY_BYTE_ARRAY,
                USER_RW.getName())
            .size());
    assertEquals(
        0,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, Bytes.toBytes("dummmyCQ"))
            .size());

    // Table Users + CF + CQ + User
    assertEquals(
        3,
        AccessControlClient.getUserPermissions(
                conn,
                table1.getNameAsString(),
                TEST_FAMILY,
                HConstants.EMPTY_BYTE_ARRAY,
                HConstants.EMPTY_STRING)
            .size());
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, TEST_QUALIFIER, USER_RW.getName())
            .size());
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, TEST_QUALIFIER2, USER_RW.getName())
            .size());
    assertEquals(
        0,
        AccessControlClient.getUserPermissions(
                conn, table1.getNameAsString(), TEST_FAMILY, TEST_QUALIFIER2, nSUser1.getName())
            .size());
  }

  protected void validateNamespaceUserACLForGetUserPermissions(
      final Connection conn,
      User nSUser1,
      User nSUser3,
      User nsGroupUser1,
      User nsGroupUser2,
      String nsPrefix,
      final String namespace1,
      String namespace2)
      throws Throwable {
    AccessTestAction namespaceUserPermissionAction =
        () -> {
          try (Connection conn1 = ConnectionFactory.createConnection(conf)) {
            conn1
                .getAdmin()
                .getUserPermissions(
                    GetUserPermissionsRequest.newBuilder(namespace1).withUserName("dummy").build());
          }
          return null;
        };
    verifyAllowed(
        namespaceUserPermissionAction,
        SUPERUSER,
        USER_GROUP_ADMIN,
        USER_ADMIN,
        nSUser1,
        nsGroupUser1);
    verifyDenied(
        namespaceUserPermissionAction,
        USER_GROUP_CREATE,
        USER_GROUP_READ,
        USER_GROUP_WRITE,
        nSUser3,
        nsGroupUser2);

    List<UserPermission> userPermissions;
    assertEquals(6, AccessControlClient.getUserPermissions(conn, "@" + nsPrefix + ".*").size());
    assertEquals(3, AccessControlClient.getUserPermissions(conn, "@" + namespace1).size());
    assertEquals(
        3,
        AccessControlClient.getUserPermissions(conn, "@" + namespace1, HConstants.EMPTY_STRING)
            .size());
    userPermissions =
        AccessControlClient.getUserPermissions(conn, "@" + namespace1, nSUser1.getName());
    verifyGetUserPermissionResult(userPermissions, 1, null, null, nSUser1.getName(), null);
    userPermissions =
        AccessControlClient.getUserPermissions(conn, "@" + namespace1, nSUser3.getName());
    verifyGetUserPermissionResult(userPermissions, 1, null, null, nSUser3.getName(), null);
    assertEquals(
        0,
        AccessControlClient.getUserPermissions(conn, "@" + namespace1, USER_ADMIN.getName())
            .size());
    // Namespace group user ACL
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(conn, "@" + namespace1, nsGroupUser1.getName())
            .size());
    assertEquals(
        1,
        AccessControlClient.getUserPermissions(conn, "@" + namespace2, nsGroupUser2.getName())
            .size());
  }

  protected void validateGlobalUserACLForGetUserPermissions(
      final Connection conn,
      User nSUser1,
      User globalGroupUser1,
      User globalGroupUser2,
      Collection<String> superUsers,
      int superUserCount)
      throws Throwable {
    // Verify action privilege
    AccessTestAction globalUserPermissionAction =
        () -> {
          try (Connection conn1 = ConnectionFactory.createConnection(conf)) {
            conn1
                .getAdmin()
                .getUserPermissions(
                    GetUserPermissionsRequest.newBuilder().withUserName("dummy").build());
          }
          return null;
        };
    verifyAllowed(globalUserPermissionAction, SUPERUSER, USER_ADMIN, USER_GROUP_ADMIN);
    verifyDenied(globalUserPermissionAction, USER_GROUP_CREATE, USER_GROUP_READ, USER_GROUP_WRITE);

    // Validate global user permission
    List<UserPermission> userPermissions;
    assertEquals(5 + superUserCount, AccessControlClient.getUserPermissions(conn, null).size());
    assertEquals(
        5 + superUserCount,
        AccessControlClient.getUserPermissions(conn, HConstants.EMPTY_STRING).size());
    assertEquals(
        5 + superUserCount,
        AccessControlClient.getUserPermissions(conn, null, HConstants.EMPTY_STRING).size());
    userPermissions = AccessControlClient.getUserPermissions(conn, null, USER_ADMIN.getName());
    verifyGetUserPermissionResult(userPermissions, 1, null, null, USER_ADMIN.getName(), superUsers);
    assertEquals(0, AccessControlClient.getUserPermissions(conn, null, nSUser1.getName()).size());
    // Global group user ACL
    assertEquals(
        1, AccessControlClient.getUserPermissions(conn, null, globalGroupUser1.getName()).size());
    assertEquals(
        2, AccessControlClient.getUserPermissions(conn, null, globalGroupUser2.getName()).size());
  }

  protected void verifyGetUserPermissionResult(
      List<UserPermission> userPermissions,
      int resultCount,
      byte[] cf,
      byte[] cq,
      String userName,
      Collection<String> superUsers) {
    assertEquals(resultCount, userPermissions.size());

    for (UserPermission perm : userPermissions) {
      if (perm.getPermission() instanceof TablePermission) {
        TablePermission tablePerm = (TablePermission) perm.getPermission();
        if (cf != null) {
          assertTrue(Bytes.equals(cf, tablePerm.getFamily()));
        }
        if (cq != null) {
          assertTrue(Bytes.equals(cq, tablePerm.getQualifier()));
        }
        if (userName != null && (superUsers == null || !superUsers.contains(perm.getUser()))) {
          assertEquals(userName, perm.getUser());
        }
      } else if (perm.getPermission() instanceof NamespacePermission
          || perm.getPermission() instanceof GlobalPermission) {
        if (userName != null && (superUsers == null || !superUsers.contains(perm.getUser()))) {
          assertEquals(userName, perm.getUser());
        }
      }
    }
  }

  protected void createTestTable(TableName tname, byte[] cf) throws Exception {
    HTableDescriptor htd = new HTableDescriptor(tname);
    HColumnDescriptor hcd = new HColumnDescriptor(cf);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);
    createTable(TEST_UTIL, TEST_UTIL.getAdmin(), htd, new byte[][] {Bytes.toBytes("s")});
  }

  protected static HTableDescriptor getHTableDescriptor() {
    HTableDescriptor htd = new HTableDescriptor(TEST_TABLE);
    HColumnDescriptor hcd = new HColumnDescriptor(TEST_FAMILY);
    hcd.setMaxVersions(100);
    htd.addFamily(hcd);
    htd.setOwner(USER_OWNER);
    return htd;
  }
}
