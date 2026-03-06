package tech.stackable.hbase.opa;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.security.access.Permission;
import org.apache.hadoop.security.UserGroupInformation;

public class OpaAllowQuery {
  public final OpaAllowQueryInput input;

  public OpaAllowQuery(OpaAllowQueryInput input) {
    this.input = input;
  }

  public static class OpaAllowQueryInput {
    public final OpaQueryUgi callerUgi;
    public final TableName table;
    public final String namespace;
    public final Permission.Action action;
    public final OpType operation;

    /**
     * Column families and their qualifiers being accessed. An empty qualifier list means CF-level
     * access; a non-empty list means KV-level access to specific qualifiers within that family.
     */
    public final Map<String, List<String>> families;

    public OpaAllowQueryInput(UserGroupInformation ugi, TableName table, Permission.Action action) {
      this(ugi, table, action, null);
    }

    public OpaAllowQueryInput(
        UserGroupInformation ugi, TableName table, Permission.Action action, OpType operation) {
      this(ugi, table, action, operation, Collections.emptyMap());
    }

    public OpaAllowQueryInput(
        UserGroupInformation ugi,
        TableName table,
        Permission.Action action,
        OpType operation,
        Map<String, List<String>> families) {
      this.callerUgi = new OpaQueryUgi(ugi);
      this.table = table;
      this.action = action;
      this.namespace = table.getNamespaceAsString();
      this.operation = operation;
      this.families = families;
    }

    public OpaAllowQueryInput(
        UserGroupInformation ugi, String namespace, Permission.Action action) {
      this.callerUgi = new OpaQueryUgi(ugi);
      this.table = null;
      this.action = action;
      this.namespace = namespace;
      this.operation = OpType.NONE;
      this.families = Collections.emptyMap();
    }
  }
}
