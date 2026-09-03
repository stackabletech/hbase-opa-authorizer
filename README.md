# Stackable Apache HBase authorizer

[Stackable Data Platform](https://stackable.tech/) | [Platform Docs](https://docs.stackable.tech/) | [Discussions](https://github.com/orgs/stackabletech/discussions) | [Discord](https://discord.gg/7kZ3BNnCAF)

This project contains a custom HBase coprocessor for Apache HBase, which is intended to be used with the [Stackable Data Platform](https://stackable.tech).
It implements authorization by making calls to ACLs defined in rego rules delivered by an OpenPolicyAgent (OPA) server in Kubernetes.

## Installation

The CoProcessor is built from source and included in the Stackable Apache HBase product image automatically.

## OPA authorizer

> [!IMPORTANT]
> The authorizer work best with product images for Apache HBase 2.6.0 (and later) as the HBase code in these versions provides more comprehensive coverage for ACL hooks.

### Configuration

The CoProcessor is only loaded and used by the HBase operator when it is declared in the product CRD.
See the [HBase operator documentation](https://docs.stackable.tech/home/stable/hbase/reference/crds) for more details.

The following configuration options are expected in `hbase-site.xml`:

- `hbase.security.authorization.opa.policy.url` : OPA endpoint URL (mandatory).
- `hbase.security.authorization.opa.policy.dryrun` : In dry-run mode no requests are sent to OPA (default: `false`).
- `hbase.security.authorization.opa.policy.cache.active` : Enable caching of policy decisions (default: `false`).
- `hbase.security.authorization.opa.policy.cache.seconds` : TTL of policy decisions in seconds (default: `60`).
- `hbase.security.authorization.opa.policy.cache.size` : Policy decision cache size (default: `1000`).

The Stackable HBase operator configures these options automatically.

### Request/Response Format

For every action a request similar to the one below is sent to OPA. The important parts of this request are:

- the fully qualified username (which is therefore guaranteed to be unique across Kerberos principals)
- the namespace
- the table (optional: omitted when e.g. creating a namespace)
- the action (one of `READ`, `WRITE`, `EXEC`, `CREATE`, `ADMIN`)

```json
{
  "input": {
    "callerUgi" : {
      "realUser" : null,
      "userName" : "readonlyuser/test-hbase-permissions.default.svc.cluster.local@CLUSTER.LOCAL",
      "shortUserName" : "readonlyuser",
      "primaryGroup" : null,
      "groups" : [ ],
      "authenticationMethod" : "KERBEROS",
      "realAuthenticationMethod" : "KERBEROS"
    },
    "table" : {
      "name" : "cHVibGljOnRlc3Q=",
      "nameAsString" : "public:test",
      "namespace" : "cHVibGlj",
      "namespaceAsString" : "public",
      "qualifier" : "dGVzdA==",
      "qualifierAsString" : "test",
      "nameWithNamespaceInclAsString" : "public:test"
    },
    "namespace" : "public",
    "action" : "READ"
    }
}
```

OPA will respond with one of the following (in the case of the latter an exception is thrown which is caught and handled internally):

```json
{"result":true}
```

or

```json
{"result":false}
```

### Covered Actions

The following actions are subject to ACL checks:

- creation, modification and deletion of namespaces
- reading a namespace descriptor
- creation and deletion of tables
- enabling and disabling of tables
- truncation and modification of tables
- reading data (`Get`, `Scan`)
- writing data (`Put`, `Append`, `Delete`)
- batch mutations

The following actions are currently excluded but will be included in future releases:

- modification of store file trackers (table, column family)
- moving, assigning and unassigning tables
- snapshot operations (create, list, clone, restore, delete)
- bulk loading of HFiles
