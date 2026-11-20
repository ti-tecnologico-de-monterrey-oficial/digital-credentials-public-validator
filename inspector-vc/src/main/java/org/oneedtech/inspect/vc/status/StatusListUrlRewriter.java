package org.oneedtech.inspect.vc.status;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Rewrites the URL a status list credential is downloaded from.
 *
 * <p>The credential keeps its signed {@code statusListCredential} URL; only the address used to
 * fetch it changes. This lets the validator reach a status list through a route that the public
 * URL does not offer from where it runs, for example a service in the same replica that publishes
 * the list under an internal host name that does not resolve there.
 *
 * <p>Rules come from the {@code STATUS_LIST_URL_REWRITES} environment variable: comma-separated
 * {@code prefix|replacement} pairs. Both sides are absolute {@code http} or {@code https} URLs
 * with a host, no user info, query or fragment, and a path ending in {@code /}. Host names with
 * underscores are not valid URL hosts and are rejected.
 *
 * <p>A URL matches a rule when its scheme and host (case-insensitive), its effective port and the
 * start of its path equal the prefix; the rest of the path and the query are appended to the
 * replacement. URLs with user info or with {@code .} or {@code ..} segments, even percent-encoded,
 * are never rewritten. The first matching rule wins; anything else is returned unchanged.
 */
public final class StatusListUrlRewriter {

  /** Environment variable that holds the rules. */
  /**
   * An encoded slash or backslash in the path: the internal server could decode it and read a
   * different path than the one the rule matched, so such URLs are not rewritten.
   */
  private static final Pattern ENCODED_SEPARATOR = Pattern.compile("%(2f|5c)", Pattern.CASE_INSENSITIVE);

  public static final String ENV_VARIABLE = "STATUS_LIST_URL_REWRITES";

  private static final StatusListUrlRewriter FROM_ENVIRONMENT =
      StatusListUrlRewriter.parse(System.getenv(ENV_VARIABLE));

  private final List<Rule> rules;

  private StatusListUrlRewriter(List<Rule> rules) {
    this.rules = List.copyOf(rules);
  }

  /**
   * Returns the rewriter configured by {@value #ENV_VARIABLE}, read once at class load.
   *
   * <p>Call it at startup so a malformed variable stops the application instead of failing every
   * validation that reads a status list.
   *
   * @return the shared rewriter; it has no rules if the variable is not set
   * @throws ExceptionInInitializerError if the variable holds an invalid rule
   */
  public static StatusListUrlRewriter fromEnvironment() {
    return FROM_ENVIRONMENT;
  }

  /**
   * Parses rules written as comma-separated {@code prefix|replacement} pairs.
   *
   * @param value the rules, or {@code null}
   * @return a rewriter with the rules in the given order; blank entries are ignored
   * @throws IllegalArgumentException if an entry lacks the {@code |} separator, or if its prefix
   *     or replacement is not a valid base URL as described in the class documentation
   */
  public static StatusListUrlRewriter parse(String value) {
    List<Rule> rules = new ArrayList<>();
    if (value != null) {
      for (String entry : value.split(",")) {
        String trimmed = entry.strip();
        if (trimmed.isEmpty()) {
          continue;
        }
        int separator = trimmed.indexOf('|');
        if (separator < 0) {
          throw new IllegalArgumentException(
              ENV_VARIABLE + ": each entry must be 'prefix|replacement', got '" + trimmed + "'");
        }
        String prefixText = trimmed.substring(0, separator).strip();
        String replacement = trimmed.substring(separator + 1).strip();
        URI prefix = requireBaseUrl(prefixText, "prefix");
        requireBaseUrl(replacement, "replacement");
        rules.add(
            new Rule(
                lower(prefix.getScheme()),
                normalizeHost(prefix.getHost()),
                effectivePort(prefix),
                prefix.getRawPath(),
                replacement));
      }
    }
    return new StatusListUrlRewriter(rules);
  }

  /**
   * Applies the first rule that matches the URL.
   *
   * @param url the URL declared by the credential
   * @return the URL to download from
   */
  public URI rewrite(URI url) {
    String rawPath = url.getRawPath();
    if (url.getScheme() == null
        || url.getHost() == null
        || url.getRawUserInfo() != null
        || rawPath == null
        || hasDotSegment(rawPath)
        || ENCODED_SEPARATOR.matcher(rawPath).find()) {
      return url;
    }
    String scheme = lower(url.getScheme());
    String host = normalizeHost(url.getHost());
    int port = effectivePort(url);
    for (Rule rule : rules) {
      if (rule.scheme.equals(scheme)
          && rule.host.equals(host)
          && rule.port == port
          && rawPath.startsWith(rule.path)) {
        String query = url.getRawQuery() == null ? "" : "?" + url.getRawQuery();
        return URI.create(rule.replacement + rawPath.substring(rule.path.length()) + query);
      }
    }
    return url;
  }

  /**
   * Checks one side of a rule.
   *
   * @param value the prefix or replacement
   * @param side {@code prefix} or {@code replacement}, for the error message
   * @return the parsed URL
   * @throws IllegalArgumentException if the value is not a valid base URL
   */
  private static URI requireBaseUrl(String value, String side) {
    URI uri;
    try {
      uri = new URI(value);
    } catch (Exception e) {
      throw invalid(side, value);
    }
    String scheme = lower(uri.getScheme() == null ? "" : uri.getScheme());
    boolean httpScheme = scheme.equals("http") || scheme.equals("https");
    boolean validPort = uri.getPort() == -1 || (uri.getPort() >= 1 && uri.getPort() <= 65535);
    String path = uri.getRawPath();
    if (!httpScheme
        || uri.getHost() == null
        || uri.getRawUserInfo() != null
        || uri.getRawQuery() != null
        || uri.getRawFragment() != null
        || !validPort
        || path == null
        || !path.endsWith("/")
        || hasDotSegment(path)) {
      throw invalid(side, value);
    }
    return uri;
  }

  /**
   * Tells whether a raw path has {@code .} or {@code ..} segments, plain or percent-encoded.
   *
   * @param rawPath the path as written in the URL
   * @return {@code true} if any segment would move within the path once decoded
   */
  private static boolean hasDotSegment(String rawPath) {
    for (String segment : rawPath.split("/", -1)) {
      String decoded = segment.toLowerCase(Locale.ROOT).replace("%2e", ".");
      if (decoded.equals(".") || decoded.equals("..")) {
        return true;
      }
    }
    return false;
  }

  private static String lower(String value) {
    return value.toLowerCase(Locale.ROOT);
  }

  private static String normalizeHost(String host) {
    String lowered = lower(host);
    return lowered.endsWith(".") ? lowered.substring(0, lowered.length() - 1) : lowered;
  }

  private static int effectivePort(URI uri) {
    if (uri.getPort() != -1) {
      return uri.getPort();
    }
    return lower(uri.getScheme()).equals("https") ? 443 : 80;
  }

  private static IllegalArgumentException invalid(String side, String value) {
    return new IllegalArgumentException(
        ENV_VARIABLE
            + ": the "
            + side
            + " must be an absolute http(s) URL with a host, no user info, query or fragment, a"
            + " valid port and a path ending in '/', got '"
            + value
            + "'");
  }

  /** A parsed rule: what a URL must match and the base it is rewritten to. */
  private record Rule(String scheme, String host, int port, String path, String replacement) {}
}
