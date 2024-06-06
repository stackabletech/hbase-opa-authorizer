package tech.stackable.hbase.opa;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.access.Permission;
import org.apache.hadoop.security.AccessControlException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.stackable.hbase.OpenPolicyAgentAccessController;

public class OpaAclChecker {
  private static final Logger LOG = LoggerFactory.getLogger(OpaAclChecker.class);
  private final boolean authorizationEnabled;
  private final boolean dryRun;
  private final boolean useCache;
  private final HttpClient httpClient = HttpClient.newHttpClient();
  private URI opaUri;
  private final ObjectMapper json;

  private final Map<String, Map<TableName, Map<Permission.Action, Boolean>>> aclCache =
      new ConcurrentHashMap<>();

  public OpaAclChecker(
      boolean authorizationEnabled, String opaPolicyUrl, boolean dryRun, boolean useCache) {
    this.authorizationEnabled = authorizationEnabled;
    this.dryRun = dryRun;
    this.useCache = useCache;

    this.json =
        new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
            .setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.NONE)
            .setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.PUBLIC_ONLY)
            .setVisibility(PropertyAccessor.GETTER, JsonAutoDetect.Visibility.PUBLIC_ONLY);

    if (authorizationEnabled) {
      if (opaPolicyUrl == null) {
        throw new OpaException.UriMissing(OpenPolicyAgentAccessController.OPA_POLICY_URL_PROP);
      }

      try {
        this.opaUri = URI.create(opaPolicyUrl);
      } catch (Exception e) {
        throw new OpaException.UriInvalid(opaUri, e);
      }
    }
  }

  public void checkPermissionInfo(User user, TableName table, Permission.Action action)
      throws AccessControlException {
    if (!this.authorizationEnabled) {
      return;
    }

    OpaAllowQuery query =
        new OpaAllowQuery(new OpaAllowQuery.OpaAllowQueryInput(user.getUGI(), table, action));

    String body;
    try {
      body = json.writeValueAsString(query);
    } catch (JsonProcessingException e) {
      throw new OpaException.SerializeFailed(e);
    }

    String prettyPrinted;
    try {
      prettyPrinted = json.writerWithDefaultPrettyPrinter().writeValueAsString(query);
    } catch (JsonProcessingException e) {
      LOG.error(
          "Could not pretty print the following request body (printing raw version instead): {}",
          body);
      throw new OpaException.SerializeFailed(e);
    }

    LOG.info("Request body:\n{}", prettyPrinted);
    if (this.dryRun) {
      LOG.info("Dry run request: omitting call.");
      return;
    }

    // inspect cache for the user/table/action combination
    var actionCache = getOpaAclCache(user, table, action);
    if (this.useCache) {
      if (actionCache.get(action) != null) {
        if (actionCache.get(action)) {
          LOG.info("Permission exists in OPA-policy-cache, by-passing policy call");
          return;
        } else {
          throw new AccessControlException("OPA denied the request (denial already cached");
        }
      }
    }

    HttpResponse<String> response;
    try {
      response =
          httpClient.send(
              HttpRequest.newBuilder(opaUri)
                  .header("Content-Type", "application/json")
                  .POST(HttpRequest.BodyPublishers.ofString(body))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      LOG.info("OPA response: {}", response.body());
    } catch (Exception e) {
      LOG.error(e.getMessage());
      throw new OpaException.QueryFailed(e);
    }

    switch (Objects.requireNonNull(response).statusCode()) {
      case 200:
        break;
      case 404:
        throw new OpaException.EndPointNotFound(opaUri.toString());
      default:
        throw new OpaException.OpaServerError(query.toString(), response);
    }

    OpaQueryResult result;
    try {
      result = json.readValue(response.body(), OpaQueryResult.class);
    } catch (JsonProcessingException e) {
      throw new OpaException.DeserializeFailed(e);
    }

    // return result after updating the cache
    if (result.result == null || !result.result) {
      updateCache(user, table, action, actionCache, Boolean.FALSE);
      throw new AccessControlException("OPA denied the request");
    } else {
      updateCache(user, table, action, actionCache, Boolean.TRUE);
    }
  }

  private void updateCache(
      User user,
      TableName table,
      Permission.Action action,
      Map<Permission.Action, Boolean> actionCache,
      Boolean actionAllowed) {
    if (this.useCache) {
      LOG.info("Updating OPA cache: {}/{}/{}/{}", user, table, action, actionAllowed);
      actionCache.put(action, actionAllowed);
    }
  }

  private Map<Permission.Action, Boolean> getOpaAclCache(
      User user, TableName table, Permission.Action action) {
    if (!aclCache.containsKey(user.getName())) {
      aclCache.put(user.getName(), new HashMap<>());
    }
    var tableCache = aclCache.get(user.getName());
    if (!tableCache.containsKey(table)) {
      tableCache.put(table, new HashMap<>());
    }
    var actionCache = tableCache.get(table);
    if (!actionCache.containsKey(action)) {
      actionCache.put(action, null);
    }
    // the Boolean for this action can now be inspected
    return actionCache;
  }

  private static class OpaQueryResult {
    // Boxed Boolean to detect not-present vs explicitly false
    public Boolean result;
  }

  public Map<String, Map<TableName, Map<Permission.Action, Boolean>>> getAclCache() {
    return aclCache;
  }
}
