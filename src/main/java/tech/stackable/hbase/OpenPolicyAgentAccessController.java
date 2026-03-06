package tech.stackable.hbase;

import com.google.common.collect.MapMaker;
import com.google.protobuf.Message;
import com.google.protobuf.RpcCallback;
import com.google.protobuf.RpcController;
import com.google.protobuf.Service;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.Cell;
import org.apache.hadoop.hbase.CompareOperator;
import org.apache.hadoop.hbase.CoprocessorEnvironment;
import org.apache.hadoop.hbase.NamespaceDescriptor;
import org.apache.hadoop.hbase.ServerName;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.Admin;
import org.apache.hadoop.hbase.client.Append;
import org.apache.hadoop.hbase.client.BalanceRequest;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Durability;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Increment;
import org.apache.hadoop.hbase.client.MasterSwitchType;
import org.apache.hadoop.hbase.client.Mutation;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.RegionInfo;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.client.SnapshotDescription;
import org.apache.hadoop.hbase.client.TableDescriptor;
import org.apache.hadoop.hbase.coprocessor.BulkLoadObserver;
import org.apache.hadoop.hbase.coprocessor.EndpointObserver;
import org.apache.hadoop.hbase.coprocessor.MasterCoprocessor;
import org.apache.hadoop.hbase.coprocessor.MasterCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.MasterObserver;
import org.apache.hadoop.hbase.coprocessor.ObserverContext;
import org.apache.hadoop.hbase.coprocessor.RegionCoprocessor;
import org.apache.hadoop.hbase.coprocessor.RegionCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.RegionObserver;
import org.apache.hadoop.hbase.coprocessor.RegionServerCoprocessor;
import org.apache.hadoop.hbase.coprocessor.RegionServerCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.RegionServerObserver;
import org.apache.hadoop.hbase.filter.ByteArrayComparable;
import org.apache.hadoop.hbase.ipc.RpcServer;
import org.apache.hadoop.hbase.protobuf.generated.AccessControlProtos;
import org.apache.hadoop.hbase.quotas.GlobalQuotaSettings;
import org.apache.hadoop.hbase.regionserver.FlushLifeCycleTracker;
import org.apache.hadoop.hbase.regionserver.InternalScanner;
import org.apache.hadoop.hbase.regionserver.MiniBatchOperationInProgress;
import org.apache.hadoop.hbase.regionserver.Region;
import org.apache.hadoop.hbase.regionserver.RegionScanner;
import org.apache.hadoop.hbase.regionserver.ScanType;
import org.apache.hadoop.hbase.regionserver.Store;
import org.apache.hadoop.hbase.regionserver.compactions.CompactionLifeCycleTracker;
import org.apache.hadoop.hbase.regionserver.compactions.CompactionRequest;
import org.apache.hadoop.hbase.replication.ReplicationEndpoint;
import org.apache.hadoop.hbase.replication.ReplicationPeerConfig;
import org.apache.hadoop.hbase.security.AccessDeniedException;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.UserProvider;
import org.apache.hadoop.hbase.security.access.AccessChecker;
import org.apache.hadoop.hbase.security.access.Permission;
import org.apache.hadoop.hbase.security.access.Permission.Action;
import org.apache.hadoop.hbase.security.access.UserPermission;
import org.apache.hadoop.hbase.util.Pair;
import org.apache.hadoop.hbase.wal.WALEdit;
import org.apache.hadoop.security.AccessControlException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.stackable.hbase.opa.OpaAclChecker;

public class OpenPolicyAgentAccessController
    implements MasterCoprocessor,
        RegionCoprocessor,
        RegionServerCoprocessor,
        AccessControlProtos.AccessControlService.Interface,
        MasterObserver,
        RegionObserver,
        RegionServerObserver,
        EndpointObserver,
        BulkLoadObserver {
  private static final Logger LOG = LoggerFactory.getLogger(OpenPolicyAgentAccessController.class);

  private UserProvider userProvider;
  private OpaAclChecker opaAclChecker;

  private boolean authorizationEnabled;

  // Opa-related
  public static final String OPA_POLICY_URL_PROP = "hbase.security.authorization.opa.policy.url";
  public static final String OPA_POLICY_DRYRUN = "hbase.security.authorization.opa.policy.dryrun";
  public static final String OPA_POLICY_CACHE =
      "hbase.security.authorization.opa.policy.cache.active";
  public static final String OPA_POLICY_CACHE_TTL_SECONDS =
      "hbase.security.authorization.opa.policy.cache.seconds";
  public static final String OPA_POLICY_CACHE_TTL_SIZE =
      "hbase.security.authorization.opa.policy.cache.size";

  // Mapping of scanner instances to the user who created them
  private final Map<InternalScanner, String> scannerOwners = new MapMaker().weakKeys().makeMap();

  @Override
  public void start(CoprocessorEnvironment env) {
    this.authorizationEnabled = AccessChecker.isAuthorizationSupported(env.getConfiguration());
    boolean dryRun = env.getConfiguration().getBoolean(OPA_POLICY_DRYRUN, false);
    boolean useCache = env.getConfiguration().getBoolean(OPA_POLICY_CACHE, false);
    int cacheTtlSeconds = env.getConfiguration().getInt(OPA_POLICY_CACHE_TTL_SECONDS, 60);
    long cacheTtlSize = env.getConfiguration().getLong(OPA_POLICY_CACHE_TTL_SIZE, 1000);

    if (!authorizationEnabled) {
      LOG.warn(
          "OpenPolicyAgentAccessController has been loaded with authorization checks DISABLED!");
    }
    if (dryRun) {
      LOG.warn("OpenPolicyAgentAccessController has been loaded in dryRun mode...");
    }

    // set the user-provider.
    this.userProvider = UserProvider.instantiate(env.getConfiguration());

    // opa-related
    this.opaAclChecker =
        new OpaAclChecker(
            authorizationEnabled,
            env.getConfiguration().get(OPA_POLICY_URL_PROP),
            dryRun,
            new OpaAclChecker.CacheConfig(useCache, cacheTtlSeconds, cacheTtlSize));
  }

  public Optional<Long> getAclCacheSize() {
    return opaAclChecker.getAclCacheSize();
  }

  private User getActiveUser(ObserverContext<?> ctx) throws IOException {
    // Returns the active user for the coprocessor call.
    // If an explicit User instance was provided to the constructor, that will be returned,
    // otherwise if we are in the context of an RPC call, the remote user is used.
    // May not be present if the execution is outside an RPC context.
    Optional<User> optionalUser = ctx.getCaller();
    if (optionalUser.isPresent()) {
      return optionalUser.get();
    }
    return userProvider.getCurrent();
  }

  @Override
  public void preCreateNamespace(
      ObserverContext<MasterCoprocessorEnvironment> c, NamespaceDescriptor ns) throws IOException {
    User user = getActiveUser(c);
    LOG.debug("preCreateNamespace: user [{}]", user);
    opaAclChecker.checkPermissionInfo(user, ns.getName(), Action.ADMIN);
  }

  @Override
  public void preDeleteNamespace(ObserverContext<MasterCoprocessorEnvironment> c, String namespace)
      throws IOException {
    User user = getActiveUser(c);
    LOG.debug("preDeleteNamespace: user [{}]", user);
    opaAclChecker.checkPermissionInfo(user, namespace, Action.ADMIN);
  }

  @Override
  public void preModifyNamespace(
      ObserverContext<MasterCoprocessorEnvironment> c, NamespaceDescriptor ns) throws IOException {
    User user = getActiveUser(c);
    LOG.debug("preModifyNamespace: user [{}]", user);
    opaAclChecker.checkPermissionInfo(user, ns.getName(), Action.ADMIN);
  }

  @Override
  public void preGetNamespaceDescriptor(
      ObserverContext<MasterCoprocessorEnvironment> c, String namespace) throws IOException {
    User user = getActiveUser(c);
    LOG.debug("preGetNamespaceDescriptor: user [{}]", user);
    opaAclChecker.checkPermissionInfo(user, namespace, Action.ADMIN);
  }

  @Override
  public void postListNamespaces(
      ObserverContext<MasterCoprocessorEnvironment> c, List<String> namespaces) throws IOException {
    /* always allow namespace listing */
  }

  @Override
  public void preCreateTable(
      ObserverContext<MasterCoprocessorEnvironment> c, TableDescriptor desc, RegionInfo[] regions)
      throws IOException {
    User user = getActiveUser(c);
    LOG.debug("preCreateTable: user [{}]", user);

    opaAclChecker.checkPermissionInfo(user, desc.getTableName(), Action.CREATE);
  }

  @Override
  public void postCompletedCreateTableAction(
      final ObserverContext<MasterCoprocessorEnvironment> c,
      final TableDescriptor desc,
      final RegionInfo[] regions) {
    /*
    The default AccessController uses this method to update the permissions for the newly created table
    in the internal ACL table. We do not need this as we are managing permissions in OPA.
     */
  }

  @Override
  public void preDeleteTable(ObserverContext<MasterCoprocessorEnvironment> c, TableName tableName)
      throws IOException {
    User user = getActiveUser(c);
    LOG.debug("preDeleteTable: user [{}]", user);

    // the default access controller treats create/delete as requiring the same permissions.
    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
  }

  @Override
  public void postDeleteTable(
      ObserverContext<MasterCoprocessorEnvironment> c, final TableName tableName) {
    /*
    The default AccessController uses this method to remove the permissions for the deleted table
    in the internal ACL table. We do not need this as we are managing permissions in OPA.
     */
  }

  @Override
  public void preEnableTable(ObserverContext<MasterCoprocessorEnvironment> c, TableName tableName)
      throws IOException {
    User user = getActiveUser(c);
    LOG.debug("preEnableTable: user [{}]", user);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
  }

  @Override
  public void preDisableTable(ObserverContext<MasterCoprocessorEnvironment> c, TableName tableName)
      throws IOException {
    User user = getActiveUser(c);
    LOG.debug("preDisableTable: user [{}]", user);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
  }

  @Override
  public void preGetOp(
      final ObserverContext<RegionCoprocessorEnvironment> c, final Get get, final List<Cell> result)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    // All users need read access to hbase:meta table.
    if (TableName.META_TABLE_NAME.equals(tableName)) {
      return;
    }
    opaAclChecker.checkPermissionInfo(user, tableName, Action.READ);
  }

  @Override
  public boolean preExists(
      final ObserverContext<RegionCoprocessorEnvironment> c, final Get get, final boolean exists)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    // All users need read access to hbase:meta table.
    if (TableName.META_TABLE_NAME.equals(tableName)) {
      return exists;
    }
    LOG.trace("preExists: user [{}] on table [{}] with get [{}]", user, tableName, get);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.READ);
    return exists;
  }

  @Override
  public void preScannerOpen(final ObserverContext<RegionCoprocessorEnvironment> c, final Scan scan)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    // All users need read access to hbase:meta table.
    if (TableName.META_TABLE_NAME.equals(tableName)) {
      return;
    }
    LOG.trace("preScannerOpen: user [{}] on table [{}] with scan [{}]", user, tableName, scan);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.READ);
  }

  @Override
  public RegionScanner postScannerOpen(
      final ObserverContext<RegionCoprocessorEnvironment> c, final Scan scan, final RegionScanner s)
      throws IOException {
    User user = getActiveUser(c);
    if (user != null && user.getShortName() != null) {
      // TODO this uses the shortName. Is it possible for the same scanner to be used by
      // different users across principals who nevertheless have the same shortName? This
      // is augmented by a specific user check via OPA, so we may not need to track the
      // scanners at all.
      scannerOwners.put(s, user.getShortName());
    }
    return s;
  }

  @Override
  public boolean preScannerNext(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final InternalScanner s,
      final List<Result> result,
      final int limit,
      final boolean hasNext)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace("preScannerNext: user [{}] on table [{}] with scan [{}]", user, tableName, s);

    requireScannerOwner(s);
    return hasNext;
  }

  @Override
  public void preScannerClose(
      final ObserverContext<RegionCoprocessorEnvironment> c, final InternalScanner s)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace("preScannerClose: user [{}] on table [{}] with scan [{}]", user, tableName, s);

    requireScannerOwner(s);
  }

  @Override
  public void postScannerClose(
      final ObserverContext<RegionCoprocessorEnvironment> c, final InternalScanner s)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace("postScannerClose: user [{}] on table [{}] with scan [{}]", user, tableName, s);

    scannerOwners.remove(s);
  }

  /** This method is copied from the code in AccessController. */
  private void requireScannerOwner(InternalScanner s) throws AccessDeniedException {
    if (!RpcServer.isInRpcCallContext()) {
      return;
    }
    String requestUserName = RpcServer.getRequestUserName().orElse(null);
    String owner = scannerOwners.get(s);
    if (authorizationEnabled && owner != null && !owner.equals(requestUserName)) {
      throw new AccessDeniedException("User '" + requestUserName + "' is not the scanner owner!");
    }
  }

  @Override
  public void prePut(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final Put put,
      final WALEdit edit,
      final Durability durability)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace("prePut: user [{}] on table [{}] with put [{}]", user, tableName, put);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
  }

  @Override
  public void preDelete(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final Delete delete,
      final WALEdit edit,
      final Durability durability)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace("preDelete: user [{}] on table [{}] with delete [{}]", user, tableName, delete);

    // the default access controller uses a second enum - OpType - to distinguish between
    // different types of write action (e.g. write, delete)
    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
  }

  @Override
  public void postDelete(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final Delete delete,
      final WALEdit edit,
      final Durability durability) {
    // not needed as we do not use the ACL table
  }

  @Override
  public Result preAppend(ObserverContext<RegionCoprocessorEnvironment> c, Append append)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace("preAppend: user [{}] on table [{}] with append [{}]", user, tableName, append);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE, Action.READ);

    // as per default access controller
    return null;
  }

  @Override
  public void preBatchMutate(
      ObserverContext<RegionCoprocessorEnvironment> c,
      MiniBatchOperationInProgress<Mutation> miniBatchOp)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace(
        "preBatchMutate: user [{}] on table [{}] with miniBatchOp [{}]",
        user,
        tableName,
        miniBatchOp);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
  }

  @Override
  public void preOpen(ObserverContext<RegionCoprocessorEnvironment> c) throws IOException {
    User user = getActiveUser(c);
    final Region region = c.getEnvironment().getRegion();
    if (region == null) {
      LOG.error("NULL region from RegionCoprocessorEnvironment in preOpen()");
    } else {
      TableName tableName = region.getRegionInfo().getTable();
      LOG.trace("preOpen: user [{}] on table [{}]", user, tableName);
      opaAclChecker.checkPermissionInfo(user, tableName, Action.ADMIN);
    }
  }

  @Override
  public void postOpen(ObserverContext<RegionCoprocessorEnvironment> c) {
    // not needed as the ACL table is not used
  }

  @Override
  public void preTableFlush(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, final TableName tableName)
      throws IOException {
    User user = getActiveUser(ctx);
    LOG.trace("preTableFlush: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
  }

  @Override
  public void preFlush(
      ObserverContext<RegionCoprocessorEnvironment> c, FlushLifeCycleTracker tracker)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace("preFlush: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
  }

  @Override
  public InternalScanner preCompact(
      ObserverContext<RegionCoprocessorEnvironment> c,
      Store store,
      InternalScanner scanner,
      ScanType scanType,
      CompactionLifeCycleTracker tracker,
      CompactionRequest request)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace("preCompact: user [{}] on table [{}] for scanner [{}]", user, tableName, scanner);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);

    return scanner;
  }

  @Override
  public void preGetTableDescriptors(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      List<TableName> tableNamesList,
      List<TableDescriptor> descriptors,
      String regex)
      throws IOException {
    // From upstream:
    // We are delegating the authorization check to postGetTableDescriptors as we don't have
    // any concrete set of table names when a regex is present or the full list is requested.
    if (regex == null && tableNamesList != null && !tableNamesList.isEmpty()) {
      User user = getActiveUser(ctx);
      TableName[] sns = null;
      try (Admin admin = ctx.getEnvironment().getConnection().getAdmin()) {
        sns = admin.listTableNames();
        if (sns == null) return;
        for (TableName tableName : tableNamesList) {
          // Skip checks for a table that does not exist
          if (!admin.tableExists(tableName)) continue;
          opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
        }
      }
    }
  }

  @Override
  public void postGetTableDescriptors(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      List<TableName> tableNamesList,
      List<TableDescriptor> descriptors,
      String regex)
      throws IOException {
    // Skipping as checks in this case are already done by preGetTableDescriptors.
    if (regex == null && tableNamesList != null && !tableNamesList.isEmpty()) {
      return;
    }
    User user = getActiveUser(ctx);
    // Retains only those which passes authorization checks, as the checks weren't done as part
    // of preGetTableDescriptors.
    Iterator<TableDescriptor> itr = descriptors.iterator();
    while (itr.hasNext()) {
      TableDescriptor htd = itr.next();
      try {
        opaAclChecker.checkPermissionInfo(user, htd.getTableName(), Action.CREATE);
      } catch (AccessControlException e) {
        itr.remove();
      }
    }
  }

  @Override
  public void postGetTableNames(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      List<TableDescriptor> descriptors,
      String regex)
      throws IOException {
    // Retains only those which passes authorization checks.
    User user = getActiveUser(ctx);
    Iterator<TableDescriptor> itr = descriptors.iterator();
    while (itr.hasNext()) {
      TableDescriptor htd = itr.next();
      try {
        opaAclChecker.checkPermissionInfo(user, htd.getTableName(), Action.CREATE);
      } catch (AccessControlException e) {
        itr.remove();
      }
    }
  }

  @Override
  public boolean preCheckAndPut(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final byte[] row,
      final byte[] family,
      final byte[] qualifier,
      final CompareOperator op,
      final ByteArrayComparable comparator,
      final Put put,
      final boolean result)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace("preCheckAndPut: user [{}] on table [{}] for put [{}]", user, tableName, put);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE, Action.READ);
    return result;
  }

  @Override
  public boolean preCheckAndPutAfterRowLock(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final byte[] row,
      final byte[] family,
      final byte[] qualifier,
      final CompareOperator opp,
      final ByteArrayComparable comparator,
      final Put put,
      final boolean result)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace(
        "preCheckAndPutAfterRowLock: user [{}] on table [{}] for put [{}]", user, tableName, put);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE, Action.READ);
    return result;
  }

  @Override
  public boolean preCheckAndDelete(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final byte[] row,
      final byte[] family,
      final byte[] qualifier,
      final CompareOperator op,
      final ByteArrayComparable comparator,
      final Delete delete,
      final boolean result)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace(
        "preCheckAndDelete: user [{}] on table [{}] for delete [{}]", user, tableName, delete);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE, Action.READ);
    return result;
  }

  @Override
  public boolean preCheckAndDeleteAfterRowLock(
      final ObserverContext<RegionCoprocessorEnvironment> c,
      final byte[] row,
      final byte[] family,
      final byte[] qualifier,
      final CompareOperator op,
      final ByteArrayComparable comparator,
      final Delete delete,
      final boolean result)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace(
        "preCheckAndDeleteAfterRowLock: user [{}] on table [{}] for delete [{}]",
        user,
        tableName,
        delete);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE, Action.READ);
    return result;
  }

  @Override
  public void postListNamespaceDescriptors(
      ObserverContext<MasterCoprocessorEnvironment> ctx, List<NamespaceDescriptor> descriptors) {
    // allow for all users
  }

  @Override
  public void preTruncateTable(
      ObserverContext<MasterCoprocessorEnvironment> c, final TableName tableName)
      throws IOException {
    User user = getActiveUser(c);
    LOG.debug("preTruncateTable: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
  }

  @Override
  public void postTruncateTable(
      ObserverContext<MasterCoprocessorEnvironment> ctx, final TableName tableName)
      throws IOException {
    User user = getActiveUser(ctx);
    LOG.trace("postTruncateTable: user [{}] on table [{}]", user, tableName);
  }

  @Override
  public TableDescriptor preModifyTable(
      ObserverContext<MasterCoprocessorEnvironment> c,
      TableName tableName,
      TableDescriptor currentDesc,
      TableDescriptor newDesc)
      throws IOException {
    User user = getActiveUser(c);
    LOG.debug("preModifyTable: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
    return currentDesc;
  }

  @Override
  public void postModifyTable(
      ObserverContext<MasterCoprocessorEnvironment> c,
      TableName tableName,
      final TableDescriptor htd)
      throws IOException {
    User user = getActiveUser(c);
    LOG.trace("postModifyTable: user [{}] on table [{}]", user, tableName);
  }

  @Override
  public Result preIncrement(
      final ObserverContext<RegionCoprocessorEnvironment> c, final Increment increment)
      throws IOException {
    User user = getActiveUser(c);
    TableName tableName = c.getEnvironment().getRegionInfo().getTable();
    LOG.trace("preIncrement: user [{}] on table [{}]", user, tableName);

    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE, Action.READ);
    // as per default controller
    return null;
  }

  @Override
  public List<Pair<Cell, Cell>> postIncrementBeforeWAL(
      ObserverContext<RegionCoprocessorEnvironment> ctx,
      Mutation mutation,
      List<Pair<Cell, Cell>> cellPairs) {
    // we have no ACL table so return as per the similar case in the default controller
    return cellPairs;
  }

  @Override
  public List<Pair<Cell, Cell>> postAppendBeforeWAL(
      ObserverContext<RegionCoprocessorEnvironment> ctx,
      Mutation mutation,
      List<Pair<Cell, Cell>> cellPairs) {
    // we have no ACL table so return as per the similar case in the default controller
    return cellPairs;
  }

  /*********************************** Will be deprecated in 4.0 ***********************************/

  @Override
  public void grant(
      RpcController controller,
      AccessControlProtos.GrantRequest request,
      RpcCallback<AccessControlProtos.GrantResponse> done) {
    LOG.trace(
        "grant for {}/{}", request.getUserPermission().getUser(), request.getUserPermission());
  }

  @Override
  public void revoke(
      RpcController controller,
      AccessControlProtos.RevokeRequest request,
      RpcCallback<AccessControlProtos.RevokeResponse> done) {
    LOG.trace(
        "revoke for {}/{}", request.getUserPermission().getUser(), request.getUserPermission());
  }

  @Override
  public void getUserPermissions(
      RpcController controller,
      AccessControlProtos.GetUserPermissionsRequest request,
      RpcCallback<AccessControlProtos.GetUserPermissionsResponse> done) {}

  @Override
  public void checkPermissions(
      RpcController controller,
      AccessControlProtos.CheckPermissionsRequest request,
      RpcCallback<AccessControlProtos.CheckPermissionsResponse> done) {}

  @Override
  public void hasPermission(
      RpcController controller,
      AccessControlProtos.HasPermissionRequest request,
      RpcCallback<AccessControlProtos.HasPermissionResponse> done) {}

  /*********************************** Observer/Service Getters ***********************************/

  @Override
  public Optional<RegionObserver> getRegionObserver() {
    return Optional.of(this);
  }

  @Override
  public Optional<MasterObserver> getMasterObserver() {
    return Optional.of(this);
  }

  @Override
  public Optional<EndpointObserver> getEndpointObserver() {
    return Optional.of(this);
  }

  @Override
  public Optional<BulkLoadObserver> getBulkLoadObserver() {
    return Optional.of(this);
  }

  @Override
  public Optional<RegionServerObserver> getRegionServerObserver() {
    return Optional.of(this);
  }

  @Override
  public String preModifyTableStoreFileTracker(
      ObserverContext<MasterCoprocessorEnvironment> c, TableName tableName, String dstSFT)
      throws IOException {
    requirePermission(
        c, "modifyTableStoreFileTracker", tableName, null, null, Action.ADMIN, Action.CREATE);
    return dstSFT;
  }

  @Override
  public String preModifyColumnFamilyStoreFileTracker(
      ObserverContext<MasterCoprocessorEnvironment> c,
      TableName tableName,
      byte[] family,
      String dstSFT)
      throws IOException {
    requirePermission(
        c,
        "modifyColumnFamilyStoreFileTracker",
        tableName,
        family,
        null,
        Action.ADMIN,
        Action.CREATE);
    return dstSFT;
  }

  @Override
  public void preMove(
      ObserverContext<MasterCoprocessorEnvironment> c,
      RegionInfo region,
      ServerName srcServer,
      ServerName destServer)
      throws IOException {
    requirePermission(c, "move", region.getTable(), null, null, Action.ADMIN);
  }

  @Override
  public void preAssign(ObserverContext<MasterCoprocessorEnvironment> c, RegionInfo regionInfo)
      throws IOException {
    requirePermission(c, "assign", regionInfo.getTable(), null, null, Action.ADMIN);
  }

  @Override
  public void preUnassign(ObserverContext<MasterCoprocessorEnvironment> c, RegionInfo regionInfo)
      throws IOException {
    requirePermission(c, "unassign", regionInfo.getTable(), null, null, Action.ADMIN);
  }

  @Override
  public void preRegionOffline(
      ObserverContext<MasterCoprocessorEnvironment> c, RegionInfo regionInfo) throws IOException {
    requirePermission(c, "regionOffline", regionInfo.getTable(), null, null, Action.ADMIN);
  }

  @Override
  public void preSnapshot(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final SnapshotDescription snapshot,
      final TableDescriptor hTableDescriptor)
      throws IOException {
    requirePermission(
        ctx,
        "snapshot " + snapshot.getName(),
        hTableDescriptor.getTableName(),
        null,
        null,
        Permission.Action.ADMIN);
  }

  @Override
  public void preListSnapshot(
      ObserverContext<MasterCoprocessorEnvironment> ctx, final SnapshotDescription snapshot)
      throws IOException {
    User user = getActiveUser(ctx);
    LOG.debug("preListSnapshot: user [{}] snapshot[{}]", user, snapshot);
    opaAclChecker.checkPermissionInfo(user, snapshot.getTableName(), Action.ADMIN);
  }

  @Override
  public void preCloneSnapshot(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final SnapshotDescription snapshot,
      final TableDescriptor hTableDescriptor)
      throws IOException {
    User user = getActiveUser(ctx);
    TableName tableName = hTableDescriptor.getTableName();
    LOG.debug("preCloneSnapshot: user [{}] snapshot[{}] table [{}]", user, snapshot, tableName);
    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
  }

  @Override
  public void preRestoreSnapshot(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final SnapshotDescription snapshot,
      final TableDescriptor hTableDescriptor)
      throws IOException {
    User user = getActiveUser(ctx);
    TableName tableName = hTableDescriptor.getTableName();
    LOG.debug("preRestoreSnapshot: user [{}] snapshot[{}] table [{}]", user, snapshot, tableName);
    opaAclChecker.checkPermissionInfo(user, tableName, Action.CREATE);
  }

  @Override
  public void preDeleteSnapshot(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, final SnapshotDescription snapshot)
      throws IOException {
    User user = getActiveUser(ctx);
    LOG.debug("preDeleteSnapshot: user [{}] snapshot[{}]", user, snapshot);
    opaAclChecker.checkPermissionInfo(user, snapshot.getTableName(), Action.ADMIN);
  }

  @Override
  public void preSplitRegion(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final TableName tableName,
      final byte[] splitRow)
      throws IOException {
    requirePermission(ctx, "split", tableName, null, null, Action.ADMIN);
  }

  @Override
  public void preBulkLoadHFile(
      ObserverContext<RegionCoprocessorEnvironment> ctx, List<Pair<byte[], String>> familyPaths)
      throws IOException {
    User user = getActiveUser(ctx);
    var tableName = ctx.getEnvironment().getRegion().getTableDescriptor().getTableName();
    LOG.debug("preBulkLoadHFile: user [{}] on table [{}]", user, tableName);
    opaAclChecker.checkPermissionInfo(user, tableName, Action.WRITE);
  }

  @Override
  public void prePrepareBulkLoad(ObserverContext<RegionCoprocessorEnvironment> ctx)
      throws IOException {
    requirePermission(
        ctx,
        "prePrepareBulkLoad",
        ctx.getEnvironment().getRegion().getTableDescriptor().getTableName(),
        null,
        null,
        Action.ADMIN,
        Action.CREATE);
  }

  @Override
  public void preCleanupBulkLoad(ObserverContext<RegionCoprocessorEnvironment> ctx)
      throws IOException {
    requirePermission(
        ctx,
        "preCleanupBulkLoad",
        ctx.getEnvironment().getRegion().getTableDescriptor().getTableName(),
        null,
        null,
        Action.ADMIN,
        Action.CREATE);
  }

  @Override
  public void preSetUserQuota(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final String userName,
      final TableName tableName,
      final GlobalQuotaSettings quotas)
      throws IOException {
    requirePermission(ctx, "setUserTableQuota", tableName, null, null, Action.ADMIN);
  }

  @Override
  public void preSetUserQuota(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final String userName,
      final String namespace,
      final GlobalQuotaSettings quotas)
      throws IOException {
    requirePermission(ctx, namespace, "setUserNamespaceQuota", Action.ADMIN);
  }

  @Override
  public void preSetTableQuota(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final TableName tableName,
      final GlobalQuotaSettings quotas)
      throws IOException {
    requirePermission(ctx, "setTableQuota", tableName, null, null, Action.ADMIN);
  }

  @Override
  public void preSetNamespaceQuota(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final String namespace,
      final GlobalQuotaSettings quotas)
      throws IOException {
    requirePermission(ctx, namespace, "setNamespaceQuota", Action.ADMIN);
  }

  @Override
  public void preMergeRegions(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, final RegionInfo[] regionsToMerge)
      throws IOException {
    requirePermission(ctx, "mergeRegions", regionsToMerge[0].getTable(), null, null, Action.ADMIN);
  }

  @Override
  public void preGetUserPermissions(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      String userName,
      String namespace,
      TableName tableName,
      byte[] family,
      byte[] qualifier)
      throws IOException {
    User user = getActiveUser(ctx);
    if (tableName != null) {
      LOG.debug("preGetUserPermissions: user [{}] on table [{}]", user, tableName);
      requirePermission(ctx, "getUserPermissions", tableName, family, qualifier, Action.ADMIN);
    } else if (namespace != null) {
      LOG.debug("preGetUserPermissions: user [{}] on namespace [{}]", user, namespace);
      requirePermission(ctx, namespace, "getUserPermissions", Action.ADMIN);
    } else {
      LOG.debug("preGetUserPermissions: user [{}] global", user);
      requirePermission(
          ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "getUserPermissions", Action.ADMIN);
    }
  }

  private void requirePermission(
      final ObserverContext<?> ctx, final String namespace, String request, Action perm)
      throws IOException {
    User user = getActiveUser(ctx);
    LOG.trace(
        "requirePermission: user [{}] namespace[{}] request [{}] permission [{}]",
        user,
        namespace,
        request,
        perm);
    opaAclChecker.checkPermissionInfo(user, namespace, perm);
  }

  private void requirePermission(
      ObserverContext<?> ctx,
      String request,
      TableName tableName,
      byte[] family,
      byte[] qualifier,
      Action... permissions)
      throws IOException {
    User user = getActiveUser(ctx);
    for (Action perm : permissions) {
      LOG.trace(
          "requirePermission: user [{}] tableName[{}] permission [{}]", user, tableName, perm);
      opaAclChecker.checkPermissionInfo(user, tableName, perm);
    }
  }

  @Override
  public void preBalance(ObserverContext<MasterCoprocessorEnvironment> ctx, BalanceRequest request)
      throws IOException {
    requirePermission(ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "balance", Action.ADMIN);
  }

  @Override
  public void preBalanceSwitch(ObserverContext<MasterCoprocessorEnvironment> ctx, boolean newValue)
      throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "balanceSwitch", Action.ADMIN);
  }

  @Override
  public void preShutdown(ObserverContext<MasterCoprocessorEnvironment> ctx) throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "shutdown", Action.ADMIN);
  }

  @Override
  public void preStopMaster(ObserverContext<MasterCoprocessorEnvironment> ctx) throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "stopMaster", Action.ADMIN);
  }

  @Override
  public void preClearDeadServers(ObserverContext<MasterCoprocessorEnvironment> ctx)
      throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "clearDeadServers", Action.ADMIN);
  }

  @Override
  public void preDecommissionRegionServers(
      ObserverContext<MasterCoprocessorEnvironment> ctx, List<ServerName> servers, boolean offload)
      throws IOException {
    requirePermission(
        ctx,
        NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR,
        "decommissionRegionServers",
        Action.ADMIN);
  }

  @Override
  public void preListDecommissionedRegionServers(ObserverContext<MasterCoprocessorEnvironment> ctx)
      throws IOException {
    requirePermission(
        ctx,
        NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR,
        "listDecommissionedRegionServers",
        Action.READ);
  }

  @Override
  public void preRecommissionRegionServer(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      ServerName server,
      List<byte[]> encodedRegionNames)
      throws IOException {
    requirePermission(
        ctx,
        NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR,
        "recommissionRegionServers",
        Action.ADMIN);
  }

  @Override
  public void preStopRegionServer(ObserverContext<RegionServerCoprocessorEnvironment> ctx)
      throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "preStopRegionServer", Action.ADMIN);
  }

  /*********************************** Not implemented (yet) ***********************************/

  @Override
  public Message preEndpointInvocation(
      ObserverContext<RegionCoprocessorEnvironment> ctx,
      Service service,
      String methodName,
      Message request) {
    LOG.debug("preEndpointInvocation not implemented! {}/{}", methodName, request);
    return request;
  }

  @Override
  public void postEndpointInvocation(
      ObserverContext<RegionCoprocessorEnvironment> ctx,
      Service service,
      String methodName,
      Message request,
      Message.Builder responseBuilder) {
    LOG.debug("postEndpointInvocation not implemented! {}/{}", methodName, request);
  }

  @Override
  public void preRequestLock(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      String namespace,
      TableName tableName,
      RegionInfo[] regionInfos,
      String description) {
    LOG.debug("preRequestLock not implemented! {}/{}", tableName, regionInfos);
  }

  @Override
  public void preLockHeartbeat(
      ObserverContext<MasterCoprocessorEnvironment> ctx, TableName tableName, String description) {
    LOG.debug("preLockHeartbeat not implemented! {}/{}", tableName, description);
  }

  /*********************************** Global admin operations ***********************************/

  @Override
  public void preAbortProcedure(
      ObserverContext<MasterCoprocessorEnvironment> ctx, final long procId) throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "abortProcedure", Action.ADMIN);
  }

  @Override
  public void postAbortProcedure(ObserverContext<MasterCoprocessorEnvironment> ctx) {
    // There is nothing to do at this time after the procedure abort request was sent.
  }

  @Override
  public void preGetProcedures(ObserverContext<MasterCoprocessorEnvironment> ctx)
      throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "getProcedures", Action.ADMIN);
  }

  @Override
  public void preGetLocks(ObserverContext<MasterCoprocessorEnvironment> ctx) throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "getLocks", Action.ADMIN);
  }

  @Override
  public void preSetSplitOrMergeEnabled(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final boolean newValue,
      final MasterSwitchType switchType)
      throws IOException {
    requirePermission(
        ctx,
        NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR,
        "setSplitOrMergeEnabled",
        Action.ADMIN);
  }

  @Override
  public void postStartMaster(ObserverContext<MasterCoprocessorEnvironment> ctx) {
    // This would be used to create an ACL table if it does not already exist.
    // We do not use an ACL table as all checks are routed to OPA.
  }

  @Override
  public void preRollWALWriterRequest(ObserverContext<RegionServerCoprocessorEnvironment> ctx)
      throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "rollWALWriterRequest", Action.ADMIN);
  }

  @Override
  public void postRollWALWriterRequest(ObserverContext<RegionServerCoprocessorEnvironment> ctx) {
    // as per default access controller
  }

  @Override
  public void preSetUserQuota(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      final String userName,
      final GlobalQuotaSettings quotas)
      throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "setUserQuota", Action.ADMIN);
  }

  @Override
  public void preSetRegionServerQuota(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      final String regionServer,
      GlobalQuotaSettings quotas)
      throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "setRegionServerQuota", Action.ADMIN);
  }

  @Override
  public ReplicationEndpoint postCreateReplicationEndPoint(
      ObserverContext<RegionServerCoprocessorEnvironment> ctx, ReplicationEndpoint endpoint) {
    return endpoint;
  }

  @Override
  public void preReplicateLogEntries(ObserverContext<RegionServerCoprocessorEnvironment> ctx)
      throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "replicateLogEntries", Action.WRITE);
  }

  @Override
  public void preClearCompactionQueues(ObserverContext<RegionServerCoprocessorEnvironment> ctx)
      throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "clearCompactionQueues", Action.ADMIN);
  }

  @Override
  public void preAddReplicationPeer(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      String peerId,
      ReplicationPeerConfig peerConfig)
      throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "addReplicationPeer", Action.ADMIN);
  }

  @Override
  public void preRemoveReplicationPeer(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, String peerId) throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "removeReplicationPeer", Action.ADMIN);
  }

  @Override
  public void preEnableReplicationPeer(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, String peerId) throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "enableReplicationPeer", Action.ADMIN);
  }

  @Override
  public void preDisableReplicationPeer(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, String peerId) throws IOException {
    requirePermission(
        ctx,
        NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR,
        "disableReplicationPeer",
        Action.ADMIN);
  }

  @Override
  public void preGetReplicationPeerConfig(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, String peerId) throws IOException {
    requirePermission(
        ctx,
        NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR,
        "getReplicationPeerConfig",
        Action.ADMIN);
  }

  @Override
  public void preUpdateReplicationPeerConfig(
      final ObserverContext<MasterCoprocessorEnvironment> ctx,
      String peerId,
      ReplicationPeerConfig peerConfig)
      throws IOException {
    requirePermission(
        ctx,
        NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR,
        "updateReplicationPeerConfig",
        Action.ADMIN);
  }

  @Override
  public void preListReplicationPeers(
      final ObserverContext<MasterCoprocessorEnvironment> ctx, String regex) throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "listReplicationPeers", Action.ADMIN);
  }

  @Override
  public void preExecuteProcedures(ObserverContext<RegionServerCoprocessorEnvironment> ctx) {
    // Not implemented: reference AC uses checkSystemOrSuperUser, a superuser mechanism
    // not applicable to OPA-based authorization.
  }

  @Override
  public void preSwitchRpcThrottle(
      ObserverContext<MasterCoprocessorEnvironment> ctx, boolean enable) throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "switchRpcThrottle", Action.ADMIN);
  }

  @Override
  public void preIsRpcThrottleEnabled(ObserverContext<MasterCoprocessorEnvironment> ctx)
      throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "isRpcThrottleEnabled", Action.ADMIN);
  }

  @Override
  public void preSwitchExceedThrottleQuota(
      ObserverContext<MasterCoprocessorEnvironment> ctx, boolean enable) throws IOException {
    requirePermission(
        ctx,
        NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR,
        "switchExceedThrottleQuota",
        Action.ADMIN);
  }

  @Override
  public void preGrant(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      UserPermission userPermission,
      boolean mergeExistingPermissions) {
    // Not implemented: permissions are managed in OPA, not via HBase ACL table operations.
  }

  @Override
  public void preRevoke(
      ObserverContext<MasterCoprocessorEnvironment> ctx, UserPermission userPermission) {
    // Not implemented: permissions are managed in OPA, not via HBase ACL table operations.
  }

  @Override
  public void preHasUserPermissions(
      ObserverContext<MasterCoprocessorEnvironment> ctx,
      String userName,
      List<Permission> permissions) {
    // Not implemented: permission checks are routed to OPA directly.
  }

  @Override
  public void preClearRegionBlockCache(ObserverContext<RegionServerCoprocessorEnvironment> ctx)
      throws IOException {
    requirePermission(
        ctx, NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR, "clearRegionBlockCache", Action.ADMIN);
  }

  @Override
  public void preUpdateRegionServerConfiguration(
      ObserverContext<RegionServerCoprocessorEnvironment> ctx, Configuration preReloadConf)
      throws IOException {
    requirePermission(
        ctx,
        NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR,
        "updateRegionServerConfiguration",
        Action.ADMIN);
  }

  @Override
  public void preUpdateMasterConfiguration(
      ObserverContext<MasterCoprocessorEnvironment> ctx, Configuration preReloadConf)
      throws IOException {
    requirePermission(
        ctx,
        NamespaceDescriptor.DEFAULT_NAMESPACE_NAME_STR,
        "updateMasterConfiguration",
        Action.ADMIN);
  }
}
