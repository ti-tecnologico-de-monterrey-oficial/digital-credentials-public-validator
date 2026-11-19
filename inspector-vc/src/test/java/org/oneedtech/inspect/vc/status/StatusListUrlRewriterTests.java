package org.oneedtech.inspect.vc.status;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

public class StatusListUrlRewriterTests {

  private static final String RULE =
      "https://dcc-services-devl.example.io/status-credential/|http://127.0.0.1:3000/status-credential/";

  private static final URI DECLARED =
      URI.create("https://dcc-services-devl.example.io/status-credential/7r5qVefUlSXR3UOpV8y6");

  private static final URI REWRITTEN =
      URI.create("http://127.0.0.1:3000/status-credential/7r5qVefUlSXR3UOpV8y6");

  @Test
  void rewritesTheMatchingPrefixAndKeepsTheRest() {
    assertEquals(REWRITTEN, StatusListUrlRewriter.parse(RULE).rewrite(DECLARED));
  }

  @Test
  void matchesRegardlessOfCaseDefaultPortOrTrailingDotInTheHost() {
    StatusListUrlRewriter rewriter = StatusListUrlRewriter.parse(RULE);
    assertAll(
        Stream.of(
                "HTTPS://DCC-Services-Devl.Example.IO/status-credential/7r5qVefUlSXR3UOpV8y6",
                "https://dcc-services-devl.example.io:443/status-credential/7r5qVefUlSXR3UOpV8y6",
                "https://dcc-services-devl.example.io./status-credential/7r5qVefUlSXR3UOpV8y6")
            .map(url -> () -> assertEquals(REWRITTEN, rewriter.rewrite(URI.create(url)), url)));
  }

  @Test
  void doesNotRewritePathsWithEncodedSlashes() {
    StatusListUrlRewriter rewriter = StatusListUrlRewriter.parse(RULE);
    assertAll(
        Stream.of(
                "https://dcc-services-devl.example.io/status-credential/a%2F..%2Fadmin",
                "https://dcc-services-devl.example.io/status-credential/a%2f..%2fadmin",
                "https://dcc-services-devl.example.io/status-credential/a%5C..%5Cadmin")
            .map(url -> () -> assertEquals(URI.create(url), rewriter.rewrite(URI.create(url)), url)));
  }

  @Test
  void keepsTheQueryAndDropsTheFragment() {
    URI declared =
        URI.create("https://dcc-services-devl.example.io/status-credential/abc?v=2#frag");
    assertEquals(
        URI.create("http://127.0.0.1:3000/status-credential/abc?v=2"),
        StatusListUrlRewriter.parse(RULE).rewrite(declared));
  }

  @Test
  void leavesUrlsWithoutAMatchingRuleUnchanged() {
    StatusListUrlRewriter rewriter =
        StatusListUrlRewriter.parse("https://otro.example.io/|http://127.0.0.1:3000/");
    assertEquals(DECLARED, rewriter.rewrite(DECLARED));
    assertEquals(DECLARED, StatusListUrlRewriter.parse(null).rewrite(DECLARED));
    assertEquals(DECLARED, StatusListUrlRewriter.parse("  ,  ").rewrite(DECLARED));
  }

  @Test
  void usesTheFirstMatchingRule() {
    StatusListUrlRewriter rewriter =
        StatusListUrlRewriter.parse(
            " https://dcc-services-devl.example.io/ | http://127.0.0.1:3000/ ,"
                + " https://dcc-services-devl.example.io/status-credential/|http://otro/");
    assertEquals(REWRITTEN, rewriter.rewrite(DECLARED));
  }

  @Test
  void neverRewritesOtherHostsUserInfoOtherPortsOrDotSegments() {
    StatusListUrlRewriter rewriter =
        StatusListUrlRewriter.parse("https://dcc-services-devl.example.io/|http://127.0.0.1:3000/");
    assertAll(
        Stream.of(
                "https://dcc-services-devl.example.io.evil.test/status-credential/x",
                "https://dcc-services-devl.example.io@evil.test/status-credential/x",
                "https://user@dcc-services-devl.example.io/status-credential/x",
                "https://dcc-services-devl.example.io:8443/status-credential/x",
                "http://dcc-services-devl.example.io/status-credential/x",
                "https://dcc-services-devl.example.io/status-credential/../admin/x",
                "https://dcc-services-devl.example.io/status-credential/%2E%2E/admin/x",
                "https://dcc-services-devl.example.io/status-credential/./x",
                "urn:uuid:7r5qVefUlSXR3UOpV8y6")
            .map(URI::create)
            .map(url -> () -> assertEquals(url, rewriter.rewrite(url), url.toString())));
  }

  @Test
  void rejectsMalformedRules() {
    Stream<String> rules =
        Stream.of(
            "https://a.example/",
            "|http://b.example/",
            "https://a.example/|",
            "https://a.example|http://b.example/",
            "https://a.example/|http://b.example",
            "ftp://a.example/|http://b.example/",
            "a.example/|http://b.example/",
            "https://user@a.example/|http://b.example/",
            "https://a.example/|http://exa mple/",
            "https://a.example/?q=/|http://b.example/",
            "https://a.example/|http://b.example/?x=/",
            "https://a.example/#f/|http://b.example/",
            "https://a.example:99999/|http://b.example/",
            "https://a.example/|http://dcc_services:3000/",
            "https://a.example/x/../|http://b.example/");
    assertAll(
        rules.map(
            rule ->
                () ->
                    assertThrows(
                        IllegalArgumentException.class,
                        () -> StatusListUrlRewriter.parse(rule),
                        rule)));
  }
}
