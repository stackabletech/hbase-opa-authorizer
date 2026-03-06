package tech.stackable.hbase.opa;

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

    public OpaAllowQueryInput(UserGroupInformation ugi, TableName table, Permission.Action action) {
      this(ugi, table, action, null);
    }

    public OpaAllowQueryInput(
        UserGroupInformation ugi, TableName table, Permission.Action action, OpType operation) {
      this.callerUgi = new OpaQueryUgi(ugi);
      this.table = table;
      this.action = action;
      this.namespace = table.getNamespaceAsString();
      this.operation = operation;
    }

    public OpaAllowQueryInput(
        UserGroupInformation ugi, String namespace, Permission.Action action) {
      this.callerUgi = new OpaQueryUgi(ugi);
      this.table = null;
      this.action = action;
      this.namespace = namespace;
      this.operation = OpType.NONE;
    }
  }
}
