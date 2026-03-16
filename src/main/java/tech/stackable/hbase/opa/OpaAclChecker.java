package tech.stackable.hbase.opa;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
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
  private final HttpClient httpClient = HttpClient.newHttpClient();
  private URI opaUri;
  private final ObjectMapper json;

  @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
  private final Optional<Cache<String, Boolean>> aclCache;

  public static class CacheConfig {
    public final boolean enabled;
    public final int ttlSeconds;
    public final long maxSize;

    public CacheConfig(boolean enabled, int ttlSeconds, long maxSize) {
      this.enabled = enabled;
      this.ttlSeconds = ttlSeconds;
      this.maxSize = maxSize;
    }
  }

  public OpaAclChecker(
      boolean authorizationEnabled, String opaPolicyUrl, boolean dryRun, CacheConfig cc) {
    this.authorizationEnabled = authorizationEnabled;
    this.dryRun = dryRun;
    this.aclCache =
        cc.enabled
            ? Optional.of(
                Caffeine.newBuilder()
                    .expireAfterWrite(cc.ttlSeconds, TimeUnit.SECONDS)
                    .maximumSize(cc.maxSize)
                    .build())
            : Optional.empty();

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

  public void checkPermissionInfoWithOp(
      User user, TableName table, Permission.Action action, OpType operation)
      throws AccessControlException {
    checkPermissionInfoWithOp(user, table, action, operation, Collections.emptyMap());
  }

  public void checkPermissionInfoWithOp(
      User user,
      TableName table,
      Permission.Action action,
      OpType operation,
      Map<String, List<String>> families)
      throws AccessControlException {
    OpaAllowQuery query =
        new OpaAllowQuery(
            new OpaAllowQuery.OpaAllowQueryInput(
                user.getUGI(), table, action, operation, families));
    this.checkPermissionInfo(query);
  }

  public void checkPermissionInfo(User user, TableName table, Permission.Action... actions)
      throws AccessControlException {
    for (Permission.Action action : actions) {
      checkPermissionInfoWithOp(user, table, action, OpType.NONE);
    }
  }

  public void checkPermissionInfo(User user, String namespace, Permission.Action action)
      throws AccessControlException {
    OpaAllowQuery query =
        new OpaAllowQuery(new OpaAllowQuery.OpaAllowQueryInput(user.getUGI(), namespace, action));
    this.checkPermissionInfo(query);
  }

  public void checkPermissionInfo(OpaAllowQuery query) throws AccessControlException {
    if (!this.authorizationEnabled) {
      return;
    }

    String body;
    try {
      body = json.writeValueAsString(query);
    } catch (JsonProcessingException e) {
      throw new OpaException.SerializeFailed(e);
    }

    if (this.dryRun) {
      try {
        String prettyPrinted = json.writerWithDefaultPrettyPrinter().writeValueAsString(query);
        LOG.trace("Request body:\n{}", prettyPrinted);
      } catch (JsonProcessingException e) {
        LOG.error(
            "Could not pretty print the following request body (printing raw version instead): {}",
            body);
        throw new OpaException.SerializeFailed(e);
      }
      LOG.debug("Dry run request: omitting call.");
      return;
    }

    if (aclCache.isPresent()) {
      final Boolean result = aclCache.get().getIfPresent(body);
      if (result != null) {
        if (result) {
          LOG.trace("Permission exists in OPA-policy-cache, by-passing policy call");
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
      LOG.trace("OPA response: {}", response.body());
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

    // Update cache
    if (aclCache.isPresent()) {
      if (result.result == null || !result.result) {
        aclCache.get().put(body, Boolean.FALSE);
      } else {
        aclCache.get().put(body, Boolean.TRUE);
      }
    }

    if (result.result == null || !result.result) {
      throw new AccessControlException("OPA denied the request");
    }
  }

  private static class OpaQueryResult {
    // Boxed Boolean to detect not-present vs explicitly false
    public Boolean result;
  }

  public Optional<Long> getAclCacheSize() {
    return aclCache.map(Cache::estimatedSize);
  }
}
