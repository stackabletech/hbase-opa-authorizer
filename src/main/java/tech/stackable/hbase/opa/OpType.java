package tech.stackable.hbase.opa;

/**
 * Region-level operation types, mirroring the OpType enum in the HBase reference AccessController.
 */
public enum OpType {
  NONE("none"),
  GET("get"),
  EXISTS("exists"),
  SCAN("scan"),
  PUT("put"),
  DELETE("delete"),
  CHECK_AND_PUT("checkAndPut"),
  CHECK_AND_DELETE("checkAndDelete"),
  APPEND("append"),
  INCREMENT("increment");

  private final String value;

  OpType(String value) {
    this.value = value;
  }

  @Override
  public String toString() {
    return value;
  }
}
