package tech.stackable.hbase;

import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.hadoop.hbase.coprocessor.BulkLoadObserver;
import org.apache.hadoop.hbase.coprocessor.EndpointObserver;
import org.apache.hadoop.hbase.coprocessor.MasterObserver;
import org.apache.hadoop.hbase.coprocessor.RegionObserver;
import org.apache.hadoop.hbase.coprocessor.RegionServerObserver;
import org.junit.Test;

/**
 * Verifies that every method in the coprocessor observer interfaces is either explicitly overridden
 * in OpenPolicyAgentAccessController or listed in the known exclusion set below.
 *
 * <p>Because all HBase observer interface methods have default implementations, adding a new hook
 * upstream would not cause a compile error. This test catches that: any new method that appears in
 * an observer interface and is not in our class or in EXCLUDED will cause a test failure.
 *
 * <p>When upgrading HBase, if this test fails, review the new method(s) and either:
 *
 * <ul>
 *   <li>Implement them in OpenPolicyAgentAccessController, or
 *   <li>Add them to the appropriate section of EXCLUDED with a justification comment.
 * </ul>
 *
 * <p>Note: all {@code post*} methods are excluded automatically — they fire after the operation has
 * already been permitted and cannot block it, so OPA enforcement is never applicable.
 */
public class TestCoprocessorInterfaceCoverage {

  private static final Class<?>[] OBSERVER_INTERFACES = {
    MasterObserver.class,
    RegionObserver.class,
    RegionServerObserver.class,
    EndpointObserver.class,
    BulkLoadObserver.class,
  };

  /**
   * Pre-hooks that are deliberately not overridden. Organised by reason. When a new HBase version
   * adds a method that belongs here, add it with a comment explaining why.
   */
  private static final Set<String> EXCLUDED =
      new HashSet<>(
          Arrays.asList(

              // --- deprecated overloads superseded by variants we do override ---
              // The WALEdit-carrying variants of data-write hooks were deprecated in HBase 2.x;
              // the 2-arg versions (which we do override) are the current API.
              "preAppend(ObserverContext, Append, WALEdit)",
              "preDelete(ObserverContext, Delete, WALEdit)",
              "preIncrement(ObserverContext, Increment, WALEdit)",
              "prePut(ObserverContext, Put, WALEdit)",
              // Old single-descriptor overload; we override the 4-arg (old + new) variant.
              "preModifyTable(ObserverContext, TableName, TableDescriptor)",
              // Old 2-descriptor namespace overload; we override the 2-arg (new descriptor only)
              // variant.
              "preModifyNamespace(ObserverContext, NamespaceDescriptor, NamespaceDescriptor)",
              // Old 3-arg unassign with boolean; we override the 2-arg variant.
              "preUnassign(ObserverContext, RegionInfo, boolean)",

              // --- after-row-lock variants where we check at the pre-lock level ---
              // HBase calls the pre-lock hook before acquiring the row lock and the after-lock hook
              // after.
              // We enforce permissions at the pre-lock level (preAppend, preIncrement), so the
              // after-lock
              // variants are redundant for OPA authorization.
              "preAppendAfterRowLock(ObserverContext, Append)",
              "preIncrementAfterRowLock(ObserverContext, Increment)",

              // --- internal HBase multi-step DDL action hooks ---
              // These are called internally by the HBase master during multi-step DDL procedures.
              // They are not triggered by direct client calls; the public pre* hooks (e.g.
              // preCreateTable)
              // are already checked before these fire.
              "preCreateTableAction(ObserverContext, TableDescriptor, RegionInfo[])",
              "preCreateTableRegionsInfos(ObserverContext, TableDescriptor)",
              "preDeleteTableAction(ObserverContext, TableName)",
              "preEnableTableAction(ObserverContext, TableName)",
              "preDisableTableAction(ObserverContext, TableName)",
              "preTruncateTableAction(ObserverContext, TableName)",
              "preTruncateRegion(ObserverContext, RegionInfo)",
              "preTruncateRegionAction(ObserverContext, RegionInfo)",
              "preModifyTableAction(ObserverContext, TableName, TableDescriptor)",
              "preModifyTableAction(ObserverContext, TableName, TableDescriptor, TableDescriptor)",
              "preMergeRegionsAction(ObserverContext, RegionInfo[])",
              "preMergeRegionsCommitAction(ObserverContext, RegionInfo[], List)",
              "preSplitRegionAction(ObserverContext, TableName, byte[])",
              "preSplitRegionBeforeMETAAction(ObserverContext, byte[], List)",
              "preSplitRegionAfterMETAAction(ObserverContext)",

              // --- internal storage, compaction, and scan hooks ---
              // These are called by HBase's internal storage engine for compaction, flush, and scan
              // operations. They are not user-initiated and carry no meaningful authorization
              // context.
              "preClose(ObserverContext, boolean)",
              "preCommitStoreFile(ObserverContext, byte[], List)",
              "preCompactScannerOpen(ObserverContext, Store, ScanType, ScanOptions, CompactionLifeCycleTracker, CompactionRequest)",
              "preCompactSelection(ObserverContext, Store, List, CompactionLifeCycleTracker)",
              "preFlush(ObserverContext, Store, InternalScanner, FlushLifeCycleTracker)",
              "preFlushScannerOpen(ObserverContext, Store, ScanOptions, FlushLifeCycleTracker)",
              "preMemStoreCompaction(ObserverContext, Store)",
              "preMemStoreCompactionCompact(ObserverContext, Store, InternalScanner)",
              "preMemStoreCompactionCompactScannerOpen(ObserverContext, Store, ScanOptions)",
              "prePrepareTimeStampForDeleteVersion(ObserverContext, Mutation, Cell, byte[], Get)",
              "preStoreFileReaderOpen(ObserverContext, FileSystem, Path, FSDataInputStreamWrapper, long, CacheConfig, Reference, StoreFileReader)",
              "preStoreScannerOpen(ObserverContext, Store, ScanOptions)",

              // --- WAL, replication, and master lifecycle hooks ---
              // Triggered by HBase internals (WAL writers, replication pipeline, master startup),
              // not by user requests.
              "preMasterInitialization(ObserverContext)",
              "preMasterStoreFlush(ObserverContext)",
              "preReplayWALs(ObserverContext, RegionInfo, Path)",
              "preWALAppend(ObserverContext, WALKey, WALEdit)",
              "preWALRestore(ObserverContext, RegionInfo, WALKey, WALEdit)",
              "preReplicationSinkBatchMutate(ObserverContext, WALEntry, Mutation)",

              // --- RSGroup management ---
              // RSGroups are an optional HBase feature for grouping RegionServers. Not yet
              // implemented.
              // All RSGroup operations should require ADMIN when implemented.
              "preAddRSGroup(ObserverContext, String)",
              "preRemoveRSGroup(ObserverContext, String)",
              "preBalanceRSGroup(ObserverContext, String, BalanceRequest)",
              "preGetRSGroupInfo(ObserverContext, String)",
              "preGetRSGroupInfoOfServer(ObserverContext, Address)",
              "preGetRSGroupInfoOfTable(ObserverContext, TableName)",
              "preListRSGroups(ObserverContext)",
              "preMoveServers(ObserverContext, Set, String)",
              "preMoveServersAndTables(ObserverContext, Set, Set, String)",
              "preMoveTables(ObserverContext, Set, String)",
              "preRemoveServers(ObserverContext, Set)",
              "preRenameRSGroup(ObserverContext, String, String)",
              "preUpdateRSGroupConfig(ObserverContext, String, Map)",

              // --- TODO: genuine gaps that need OPA implementation ---
              // These pre-hooks are user-facing and should enforce OPA permissions, but are not yet
              // implemented. They are excluded here to keep this test focused on detecting new
              // upstream methods.
              //
              // Metadata listing hooks: getTableNames is covered post-hoc by postGetTableNames
              // filtering; listNamespace* hooks are not currently enforced.
              "preGetTableNames(ObserverContext, List, String)",
              "preListNamespaceDescriptors(ObserverContext, List)",
              "preListNamespaces(ObserverContext, List)",
              // Cluster metrics: currently unenforced; reference AC requires ADMIN.
              "preGetClusterMetrics(ObserverContext)"));

  @Test
  public void testAllObserverMethodsAreExplicitlyOverridden() {
    Set<String> interfaceMethodSigs =
        Arrays.stream(OBSERVER_INTERFACES)
            .flatMap(iface -> Arrays.stream(iface.getDeclaredMethods()))
            .filter(m -> !m.isSynthetic() && !Modifier.isStatic(m.getModifiers()))
            .map(TestCoprocessorInterfaceCoverage::signature)
            .collect(Collectors.toSet());

    Set<String> ourMethodSigs =
        Arrays.stream(OpenPolicyAgentAccessController.class.getDeclaredMethods())
            .filter(m -> !m.isSynthetic())
            .map(TestCoprocessorInterfaceCoverage::signature)
            .collect(Collectors.toSet());

    List<String> unhandled =
        interfaceMethodSigs.stream()
            .filter(sig -> !sig.startsWith("post")) // post hooks can never block operations
            .filter(sig -> !EXCLUDED.contains(sig))
            .filter(sig -> !ourMethodSigs.contains(sig))
            .sorted()
            .collect(Collectors.toList());

    assertTrue(
        "Observer interface pre-hooks found that are neither overridden nor in the exclusion list"
            + " — review each and either implement it or add it to EXCLUDED with a justification:\n"
            + String.join("\n", unhandled),
        unhandled.isEmpty());
  }

  private static String signature(Method m) {
    String params =
        Arrays.stream(m.getParameterTypes())
            .map(Class::getSimpleName)
            .collect(Collectors.joining(", "));
    return m.getName() + "(" + params + ")";
  }
}
