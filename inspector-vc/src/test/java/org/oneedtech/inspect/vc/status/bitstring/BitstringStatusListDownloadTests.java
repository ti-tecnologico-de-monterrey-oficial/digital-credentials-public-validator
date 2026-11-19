package org.oneedtech.inspect.vc.status.bitstring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.CharSource;
import com.google.common.io.Resources;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItem;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.resource.StringResource;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.util.resource.detect.TypeDetector;
import org.oneedtech.inspect.vc.BitstringStatusListCredentialInspector;
import org.oneedtech.inspect.vc.probe.RunContextKey;
import org.oneedtech.inspect.vc.probe.did.SimpleDidResolver;
import org.oneedtech.inspect.vc.status.StatusListUrlRewriter;

/** Downloads of the status list, counted with a local HTTP server. */
public class BitstringStatusListDownloadTests {

  private static final String DECLARED_BASE = "https://status.example.test/status-credential/";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private HttpServer server;
  private final List<String> requests = new CopyOnWriteArrayList<>();
  private final List<String> acceptHeaders = new CopyOnWriteArrayList<>();
  private volatile int status = 200;
  private volatile String contentType = "application/json";
  private volatile byte[] body;
  private volatile boolean chunked;
  private final Map<String, String> redirects = new ConcurrentHashMap<>();

  @BeforeEach
  void startServer() throws IOException {
    body = resource("ob30/bit-string-list/testlist");
    server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext(
        "/",
        exchange -> {
          requests.add(exchange.getRequestURI().toString());
          acceptHeaders.add(String.valueOf(exchange.getRequestHeaders().getFirst("Accept")));
          String location = redirects.get(exchange.getRequestURI().getPath());
          if (location != null) {
            exchange.getResponseHeaders().set("Location", location);
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
            return;
          }
          if (contentType != null) {
            exchange.getResponseHeaders().set("Content-Type", contentType);
          }
          byte[] payload = body;
          if (exchange.getRequestMethod().equals("HEAD")) {
            exchange.sendResponseHeaders(status, -1);
          } else {
            exchange.sendResponseHeaders(status, chunked ? 0 : payload.length);
            try (OutputStream out = exchange.getResponseBody()) {
              out.write(payload);
            }
          }
          exchange.close();
        });
    server.start();
  }

  @AfterEach
  void stopServer() {
    server.stop(0);
  }

  private String internalBase() {
    return "http://127.0.0.1:" + server.getAddress().getPort() + "/internal/";
  }

  private BitstringStatusListProbe probe() {
    return new BitstringStatusListProbe(
        StatusListUrlRewriter.parse(DECLARED_BASE + "|" + internalBase()));
  }

  private static RunContext context() {
    BitstringStatusListCredentialInspector inspector =
        new BitstringStatusListCredentialInspector.Builder()
            .set(Behavior.TEST_INCLUDE_SUCCESS, true)
            .build();
    Resource credential = new StringResource(CharSource.wrap("{}"), "urn:test:credential");
    return new RunContext.Builder()
        .put(inspector)
        .put(credential)
        .put(RunContextKey.DID_RESOLVER, new SimpleDidResolver(null, null))
        .build();
  }

  private static JsonNode entry(String statusListCredential, String index) throws IOException {
    return MAPPER.readTree(
        "{\"type\":\"BitstringStatusListEntry\",\"statusPurpose\":\"revocation\","
            + "\"statusListIndex\":\""
            + index
            + "\",\"statusListCredential\":\""
            + statusListCredential
            + "\"}");
  }

  private static byte[] resource(String path) throws IOException {
    return Resources.toByteArray(Resources.getResource(path));
  }

  private static ReportItem single(ReportItems items) {
    List<ReportItem> list = new ArrayList<>();
    items.forEach(list::add);
    assertEquals(1, list.size(), list.toString());
    return list.get(0);
  }

  @Test
  void downloadsTheListOnceFromTheRewrittenAddress() throws Exception {
    ReportItem revoked = single(probe().run(entry(DECLARED_BASE + "3", "23"), context()));
    assertEquals(List.of("/internal/3"), requests);
    assertEquals(Outcome.FATAL, revoked.getOutcome(), revoked.toString());
    assertEquals("Credential has been revoked", revoked.getMessage());

    requests.clear();
    ReportItem valid = single(probe().run(entry(DECLARED_BASE + "3", "0"), context()));
    assertEquals(List.of("/internal/3"), requests);
    assertEquals(Outcome.VALID, valid.getOutcome(), valid.toString());
  }

  @Test
  void sendsTheAcceptHeaderOfUriResource() throws Exception {
    URI url = URI.create(internalBase() + "3");
    new UriResource(url, null, BitstringStatusListProbe.STATUS_LIST_TYPES).exists();
    DownloadedResource.download(url, true, BitstringStatusListProbe.STATUS_LIST_TYPES, 1 << 20);
    assertEquals(2, acceptHeaders.size());
    assertEquals(acceptHeaders.get(0), acceptHeaders.get(1));
  }

  @Test
  void unreadableListNamesTheDeclaredUrl() throws Exception {
    status = 404;
    ReportItem item = single(probe().run(entry(DECLARED_BASE + "3", "0"), context()));
    assertEquals(List.of("/internal/3"), requests);
    assertEquals(Outcome.EXCEPTION, item.getOutcome());
    assertEquals(
        "Could not process the status list credential at " + DECLARED_BASE + "3",
        item.getMessage());
    assertFalse(item.toString().contains("127.0.0.1"), item.toString());
  }

  @Test
  void invalidListNamesTheDeclaredUrl() throws Exception {
    body = "{\"not\":\"a status list\"}".getBytes();
    ReportItem item = single(probe().run(entry(DECLARED_BASE + "3", "0"), context()));
    assertEquals(1, requests.size());
    assertEquals(Outcome.ERROR, item.getOutcome());
    assertEquals(
        "The status list credential at " + DECLARED_BASE + "3 is not valid", item.getMessage());
  }

  @Test
  void onlyHttpListsAreDownloaded() throws Exception {
    ReportItem item = single(probe().run(entry("file:///etc/hostname", "0"), context()));
    assertEquals(Outcome.EXCEPTION, item.getOutcome());
    ReportItem relative = single(probe().run(entry("status/3", "0"), context()));
    assertEquals(Outcome.ERROR, relative.getOutcome());
    assertEquals(List.of(), requests);
  }

  @Test
  void rejectsBodiesLargerThanTheLimit() throws Exception {
    URI url = URI.create(internalBase() + "3");
    body = new byte[2048];
    assertThrows(
        IOException.class,
        () -> DownloadedResource.download(
                url, true, BitstringStatusListProbe.STATUS_LIST_TYPES, 1024));
    chunked = true;
    assertThrows(
        IOException.class,
        () -> DownloadedResource.download(
                url, true, BitstringStatusListProbe.STATUS_LIST_TYPES, 1024));
    body = new byte[1024];
    assertEquals(
        1024,
        DownloadedResource.download(
                url, true, BitstringStatusListProbe.STATUS_LIST_TYPES, 1024)
            .asByteSource()
            .read()
            .length);
  }

  /** The type the status list inspector ends up with, as CredentialParseProbe computes it. */
  private static ResourceType parsedType(Resource resource) throws Exception {
    ResourceType type = resource.getType();
    if (type == null || type == ResourceType.UNKNOWN) {
      Optional<ResourceType> detected = TypeDetector.detect(resource, true);
      return detected.orElse(null);
    }
    return type;
  }

  @Test
  void detectsTheSameTypeAsUriResource() throws Exception {
    List<byte[]> bodies = List.of(resource("ob30/bit-string-list/testlist"), resource("ob30/simple.jwt"));
    List<String> contentTypes =
        Arrays.asList(
            "application/json",
            "application/ld+json; charset=utf-8",
            "application/vc+ld+json",
            "application/vc+jwt",
            "text/plain",
            "application/octet-stream",
            null);
    List<String> paths = List.of("3", "3.json", "3.jwt");
    for (byte[] payload : bodies) {
      for (String type : contentTypes) {
        for (String path : paths) {
          body = payload;
          contentType = type;
          URI url = URI.create(internalBase() + path);
          ResourceType expected =
              parsedType(new UriResource(url, null, BitstringStatusListProbe.STATUS_LIST_TYPES));
          ResourceType actual =
              parsedType(
                  DownloadedResource.download(
                      url, true, BitstringStatusListProbe.STATUS_LIST_TYPES, 1 << 20));
          assertEquals(expected, actual, type + " " + path);
        }
      }
    }
  }

  @Test
  void followsRedirectsOnTheRewrittenOrigin() throws Exception {
    redirects.put("/internal/moved", "/internal/3");
    ReportItem revoked = single(probe().run(entry(DECLARED_BASE + "moved", "23"), context()));
    assertEquals(List.of("/internal/moved", "/internal/3"), requests);
    assertEquals(Outcome.FATAL, revoked.getOutcome(), revoked.toString());
  }

  @Test
  void refusesRedirectsToAnotherInternalOrigin() throws Exception {
    redirects.put(
        "/internal/moved", "http://localhost:" + server.getAddress().getPort() + "/internal/3");
    ReportItem item = single(probe().run(entry(DECLARED_BASE + "moved", "0"), context()));
    assertEquals(List.of("/internal/moved"), requests);
    assertEquals(Outcome.EXCEPTION, item.getOutcome());
    assertEquals(
        "Could not process the status list credential at " + DECLARED_BASE + "moved",
        item.getMessage());
  }

  @Test
  void stopsAfterTooManyRedirects() {
    redirects.put("/internal/loop", "/internal/loop");
    URI url = URI.create(internalBase() + "loop");
    assertThrows(
        IOException.class,
        () ->
            DownloadedResource.download(
                url, true, BitstringStatusListProbe.STATUS_LIST_TYPES, 1024));
    assertEquals(DownloadedResource.MAX_REDIRECTS + 1, requests.size());
  }

  @Test
  void refusesInternalHostsThatWereNotRewritten() throws Exception {
    BitstringStatusListProbe withoutRules = new BitstringStatusListProbe(StatusListUrlRewriter.parse(null));
    List<String> declared =
        List.of(
            internalBase() + "3",
            "http://localhost:" + server.getAddress().getPort() + "/internal/3",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/status/3",
            "http://172.16.0.1/status/3",
            "http://192.168.1.1/status/3",
            "http://0.0.0.0/status/3",
            "http://168.63.129.16/status/3",
            "http://[::1]/status/3",
            "http://[fd00::1]/status/3",
            "http://[fe80::1]/status/3",
            "http://[::ffff:127.0.0.1]/status/3");
    for (String url : declared) {
      ReportItem item = single(withoutRules.run(entry(url, "0"), context()));
      assertEquals(Outcome.EXCEPTION, item.getOutcome(), url);
      assertEquals("Could not process the status list credential at " + url, item.getMessage());
    }
    assertEquals(List.of(), requests);
  }

  @Test
  void publicAddressesAreAllowed() throws Exception {
    for (String address : List.of("8.8.8.8", "20.94.0.1", "2001:4860:4860::8888")) {
      assertFalse(DownloadedResource.isInternal(InetAddress.getByName(address)), address);
    }
    for (String address : List.of("127.0.0.1", "10.1.2.3", "169.254.169.254", "fc00::1", "ff02::1")) {
      assertTrue(DownloadedResource.isInternal(InetAddress.getByName(address)), address);
    }
  }

  @Test
  void refusesSpecialPurposeAndEmbeddedPrivateAddresses() throws Exception {
    for (String address :
        List.of(
            "100.64.1.1",
            "198.18.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "64:ff9b::a00:1",
            "2002:a00:1::1",
            "::a00:1")) {
      assertTrue(DownloadedResource.isInternal(InetAddress.getByName(address)), address);
    }
    assertFalse(DownloadedResource.isInternal(InetAddress.getByName("2002:808:808::1")));
    assertFalse(DownloadedResource.isInternal(InetAddress.getByName("64:ff9b::808:808")));
  }

  @Test
  void missingStatusPurposeIsAnErrorWithoutDownloading() throws Exception {
    JsonNode entry =
        MAPPER.readTree(
            "{\"type\":\"BitstringStatusListEntry\",\"statusListIndex\":\"0\","
                + "\"statusListCredential\":\""
                + DECLARED_BASE
                + "3\"}");
    ReportItem item = single(probe().run(entry, context()));
    assertEquals(Outcome.ERROR, item.getOutcome(), item.toString());
    assertEquals(List.of(), requests);
  }
}