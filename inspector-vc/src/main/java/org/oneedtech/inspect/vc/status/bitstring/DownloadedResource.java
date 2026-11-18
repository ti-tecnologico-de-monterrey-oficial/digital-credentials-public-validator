package org.oneedtech.inspect.vc.status.bitstring;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

import org.oneedtech.inspect.util.resource.MimeType;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.util.resource.detect.TypeDetector;

import com.google.common.io.ByteSource;

/**
 * A document downloaded once over {@code http} or {@code https} and kept in memory: a status list
 * credential, or the credential a {@code refreshService} points to.
 *
 * <p>{@link UriResource} opens a new connection on every {@code exists()}, {@code getType()} and
 * {@code asByteSource()}, and the inspectors call them several times per run. This resource answers
 * them from the single response it was built from, with the same results: {@code getType()} follows
 * the {@code Content-Type} rules of {@link UriResource#getType()}, and {@code toURI()} is the
 * address the download started from (not the last redirect), so type detection by file extension
 * and relative references behave as with a {@link UriResource}.
 */
public final class DownloadedResource extends UriResource {

  private final byte[] body;
  private final String contentType;

  private DownloadedResource(
      URI uri, List<ResourceType> acceptedTypes, byte[] body, String contentType) {
    super(uri, null, acceptedTypes);
    this.body = body;
    this.contentType = contentType;
  }

  /**
   * Downloads a document, following at most {@value #MAX_REDIRECTS} redirects.
   *
   * <p>Each hop must be {@code http} or {@code https}. A hop that is not trusted must resolve only
   * to public addresses (see {@link #isInternal(InetAddress)}). The first hop is trusted when it
   * comes from a {@code STATUS_LIST_URL_REWRITES} rule; a redirect keeps that trust only while it
   * stays on the same scheme, host and port.
   *
   * <p>The address is checked before connecting and {@link HttpURLConnection} resolves the host
   * again when it connects. Both lookups go through the JVM DNS cache, which keeps a positive answer
   * for 30 seconds by default, so they get the same addresses; {@code networkaddress.cache.ttl} must
   * not be set to 0 or a DNS server could change its answer between both lookups.
   *
   * <p>Each connection has its own connect and read timeouts, and the whole body must arrive within
   * {@value #READ_DEADLINE_MILLIS} milliseconds.
   *
   * @param uri the address to download from
   * @param trusted whether {@code uri} is the target of a rewrite rule, which may be internal
   * @param acceptedTypes the types sent in the {@code Accept} header, as {@link UriResource} does
   * @param maxBytes the largest body accepted
   * @return the downloaded resource; its {@code toURI()} is {@code uri}, as with a
   *     {@link UriResource} that followed redirects
   * @throws IOException if a hop is refused, the request fails or is too slow, the final response
   *     is not 2xx, there are too many redirects or the body is larger than {@code maxBytes}
   */
  public static DownloadedResource download(
      URI uri, boolean trusted, List<ResourceType> acceptedTypes, int maxBytes)
      throws IOException {
    URI canonical = uri.normalize();
    String accept =
        acceptedTypes.stream()
            .map(ResourceType::getMimeType)
            .map(MimeType::toString)
            .collect(Collectors.joining(", "));
    URI current = canonical;
    boolean currentTrusted = trusted;
    for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
      requireHttp(current);
      if (!currentTrusted) {
        requirePublicHost(current.getHost());
      }
      HttpURLConnection http = (HttpURLConnection) current.toURL().openConnection();
      http.setInstanceFollowRedirects(false);
      http.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
      http.setReadTimeout(READ_TIMEOUT_MILLIS);
      http.setRequestProperty("Accept", accept);
      boolean read = false;
      try {
        int status = http.getResponseCode();
        if (status >= 300 && status <= 399 && http.getHeaderField("Location") != null) {
          URI next = resolveLocation(current, http.getHeaderField("Location"));
          currentTrusted = currentTrusted && sameOrigin(current, next);
          current = next;
          continue;
        }
        if (status < 200 || status > 299) {
          throw new IOException("HTTP " + status);
        }
        if (http.getContentLengthLong() > maxBytes) {
          throw new IOException("document larger than " + maxBytes + " bytes");
        }
        byte[] body;
        try (InputStream in = http.getInputStream()) {
          body = readAtMost(in, maxBytes, System.nanoTime() + READ_DEADLINE_MILLIS * 1_000_000L);
        }
        read = true;
        return new DownloadedResource(canonical, acceptedTypes, body, http.getContentType());
      } finally {
        if (!read) {
          // The connection may still hold an unread body: drop it instead of reusing it.
          http.disconnect();
        }
      }
    }
    throw new IOException("too many redirects");
  }

  /** Redirects followed before giving up, the same limit as {@link HttpURLConnection}'s own. */
  static final int MAX_REDIRECTS = 5;

  static final int CONNECT_TIMEOUT_MILLIS = 10_000;
  static final int READ_TIMEOUT_MILLIS = 20_000;
  static final int READ_DEADLINE_MILLIS = 30_000;

  private static void requireHttp(URI uri) throws IOException {
    String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
    if ((!scheme.equals("http") && !scheme.equals("https")) || uri.getHost() == null) {
      throw new IOException("only http and https documents are downloaded");
    }
  }

  private static URI resolveLocation(URI current, String location) throws IOException {
    try {
      return current.resolve(new URI(location.strip())).normalize();
    } catch (URISyntaxException | IllegalArgumentException e) {
      throw new IOException("invalid redirect location");
    }
  }

  private static boolean sameOrigin(URI a, URI b) {
    return a.getScheme().equalsIgnoreCase(b.getScheme() == null ? "" : b.getScheme())
        && a.getHost().equalsIgnoreCase(b.getHost() == null ? "" : b.getHost())
        && effectivePort(a) == effectivePort(b);
  }

  private static int effectivePort(URI uri) {
    if (uri.getPort() != -1) {
      return uri.getPort();
    }
    return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
  }

  /**
   * Refuses a host that resolves to any address that is not public.
   *
   * @param host the host of the URL, a name or a literal address
   * @throws IOException if the host does not resolve or one of its addresses is internal
   */
  static void requirePublicHost(String host) throws IOException {
    String name =
        host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
    InetAddress[] addresses;
    try {
      addresses = InetAddress.getAllByName(name);
    } catch (UnknownHostException e) {
      throw new IOException("unknown host");
    }
    for (InetAddress address : addresses) {
      if (isInternal(address)) {
        throw new IOException("host resolves to an internal address");
      }
    }
  }

  /**
   * Whether an address is not public: loopback, private, link-local (including the cloud metadata
   * address 169.254.169.254), wildcard, multicast, shared (100.64.0.0/10, used by Azure Container
   * Apps), benchmarking (198.18.0.0/15), reserved (240.0.0.0/4 and broadcast), IPv6 unique local,
   * the Azure platform address 168.63.129.16, and the IPv6 forms that carry an IPv4 address
   * (NAT64 64:ff9b::/96, 6to4 2002::/16 and IPv4-compatible ::/96) when that IPv4 is internal.
   */
  static boolean isInternal(InetAddress address) {
    if (address.isLoopbackAddress()
        || address.isSiteLocalAddress()
        || address.isLinkLocalAddress()
        || address.isAnyLocalAddress()
        || address.isMulticastAddress()) {
      return true;
    }
    byte[] bytes = address.getAddress();
    if (address instanceof Inet6Address) {
      if ((bytes[0] & 0xfe) == 0xfc) {
        return true;
      }
      byte[] embedded = embeddedIpv4(bytes);
      return embedded != null && isInternal(ipv4(embedded));
    }
    int first = bytes[0] & 0xff;
    int second = bytes[1] & 0xff;
    // 0.0.0.0/8 reaches the local host on Linux, like the wildcard address. 168.63.129.16 is
    // public, but Azure answers it from the platform (DNS, health and agent endpoints).
    return first == 0
        || (first == 100 && (second & 0xc0) == 64)
        || (first == 198 && (second & 0xfe) == 18)
        || first >= 240
        || (first == 168 && second == 63 && (bytes[2] & 0xff) == 129 && (bytes[3] & 0xff) == 16);
  }

  private static byte[] embeddedIpv4(byte[] ipv6) {
    boolean nat64 =
        (ipv6[0] & 0xff) == 0x00 && (ipv6[1] & 0xff) == 0x64
            && (ipv6[2] & 0xff) == 0xff && (ipv6[3] & 0xff) == 0x9b
            && allZero(ipv6, 4, 12);
    if (nat64) {
      return Arrays.copyOfRange(ipv6, 12, 16);
    }
    if ((ipv6[0] & 0xff) == 0x20 && (ipv6[1] & 0xff) == 0x02) {
      return Arrays.copyOfRange(ipv6, 2, 6);
    }
    if (allZero(ipv6, 0, 12) && !allZero(ipv6, 12, 16)) {
      return Arrays.copyOfRange(ipv6, 12, 16);
    }
    return null;
  }

  private static boolean allZero(byte[] bytes, int from, int to) {
    for (int i = from; i < to; i++) {
      if (bytes[i] != 0) {
        return false;
      }
    }
    return true;
  }

  private static Inet4Address ipv4(byte[] bytes) {
    try {
      return (Inet4Address) InetAddress.getByAddress(bytes);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException(e);
    }
  }

  private static byte[] readAtMost(InputStream in, int maxBytes, long deadlineNanos)
      throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int count;
    while ((count = in.read(buffer)) != -1) {
      if (out.size() + count > maxBytes) {
        throw new IOException("document larger than " + maxBytes + " bytes");
      }
      if (System.nanoTime() > deadlineNanos) {
        throw new IOException("document took longer than " + READ_DEADLINE_MILLIS + " ms to arrive");
      }
      out.write(buffer, 0, count);
    }
    return out.toByteArray();
  }

  @Override
  public ByteSource asByteSource() {
    return ByteSource.wrap(body);
  }

  @Override
  public boolean exists() {
    return true;
  }

  @Override
  public Long getSize() {
    return (long) body.length;
  }

  /** Same rules as {@link UriResource#getType()}, applied to the stored response. */
  @Override
  public ResourceType getType() {
    if (type != null && !type.equals(ResourceType.UNKNOWN)) {
      return type;
    }
    if (contentType != null && acceptedResourceTypes != null) {
      try {
        MimeType mimeType = new MimeType(contentType);
        Optional<ResourceType> accepted =
            acceptedResourceTypes.stream()
                .filter(t -> t.getMimeType().equals(mimeType))
                .findFirst();
        if (accepted.isPresent()) {
          if (accepted.get().getMimeType().equals(MimeType.TEXT_PLAIN)) {
            Optional<ResourceType> detected =
                TypeDetector.detect(asByteSource(), canonicalURI.toURL(), null);
            if (detected.isPresent()) {
              return detected.get();
            }
          }
          return accepted.get();
        }
      } catch (Exception e) {
        // UriResource falls back to the declared type when the header cannot be read.
      }
    }
    return type;
  }
}
