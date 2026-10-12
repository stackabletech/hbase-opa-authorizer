package tech.stackable.hbase;

import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ServeEventListener;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;

/** Passes every OPA request/response pair WireMock serves to {@link OpaFixtureWriter}. */
public class OpaFixtureCapture implements ServeEventListener {
  @Override
  public String getName() {
    return "opa-fixture-capture";
  }

  @Override
  public void afterComplete(ServeEvent serveEvent, Parameters parameters) {
    OpaFixtureWriter.capture(
        serveEvent.getRequest().getBodyAsString(), serveEvent.getResponse().getBodyAsString());
  }
}
