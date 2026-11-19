package org.oneedtech.inspect.vc.status.bitstring;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.vc.BitstringStatusListCredentialInspector;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.probe.RunContextKey;
import org.oneedtech.inspect.vc.status.StatusListUrlRewriter;

import com.apicatalog.multibase.MultibaseDecoder;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * Follows algorithm defined at https://w3c.github.io/vc-bitstring-status-list/#validate-algorithm
 */
public class BitstringStatusListProbe extends Probe<JsonNode> {

  private final StatusListUrlRewriter rewriter;

  public BitstringStatusListProbe() {
    this(StatusListUrlRewriter.fromEnvironment());
  }

  BitstringStatusListProbe(StatusListUrlRewriter rewriter) {
    super(ID, TITLE);
    this.rewriter = rewriter;
  }

  @Override
  public ReportItems run(JsonNode credentialStatus, RunContext ctx) {
    // 2. Let minimumNumberOfEntries be 131,072 unless a different lower bound is established by a
    // specific ecosystem specification.
    int minimumNumberOfEntries = 131_072;

    // 3. Let status purpose be the value of statusPurpose in the credentialStatus entry in the
    // credentialToValidate.
    if (!credentialStatus.hasNonNull("statusPurpose")) {
      return error("statusPurpose is missing", ctx);
    }
    String statusPurpose = credentialStatus.get("statusPurpose").asText().strip();

    // The size of the status entry in bits, read with the same rules as statusListIndex.
    long statusSize =
        credentialStatus.hasNonNull("statusSize")
            ? statusListIndex(credentialStatus.get("statusSize"))
            : 1;
    if (statusSize <= 0 || statusSize > Integer.MAX_VALUE) {
      return error("statusSize must be a positive integer", ctx);
    }

    // 7. Let credentialIndex be the value of the statusListIndex property of the
    // BitstringStatusListEntry. It is read before downloading the list so a malformed entry does
    // not cost a request.
    long credentialIndex = statusListIndex(credentialStatus.get("statusListIndex"));
    if (credentialIndex < 0) {
      return error("statusListIndex must be a non-negative integer", ctx);
    }
    if (credentialIndex > Integer.MAX_VALUE) {
      return error(
          "credentialIndex multiplied by the size is a value outside of the range of the"
              + " bitstring",
          ctx);
    }

    // 4. Dereference the statusListCredential URL, and ensure that all proofs verify successfully
    URI statusListCredentialUrl;
    try {
      statusListCredentialUrl = new URI(credentialStatus.get("statusListCredential").asText());
    } catch (Exception e) {
      return error("statusListCredential is not a valid URI", ctx);
    }
    if (!statusListCredentialUrl.isAbsolute()) {
      return error("statusListCredential is not a valid URI", ctx);
    }
    URI downloadUrl = rewriter.rewrite(statusListCredentialUrl);

    // Downloaded once: the inspector reads the resource about ten times, and a UriResource would
    // open a connection on each read. Only a rewritten address, set by the deployment, may point
    // to an internal host; the URL a credential declares must resolve to public addresses.
    boolean rewritten = !downloadUrl.equals(statusListCredentialUrl);
    DownloadedResource statusListResource;
    try {
      statusListResource =
          DownloadedResource.download(
              downloadUrl, rewritten, STATUS_LIST_TYPES, MAX_STATUS_LIST_BYTES);
    } catch (IOException | RuntimeException e) {
      return statusListUnreadable(statusListCredentialUrl);
    }

    BitstringStatusListCredentialInspector inspector =
        new BitstringStatusListCredentialInspector.Builder()
            .inject(RunContextKey.DID_RESOLVER, ctx.get(RunContextKey.DID_RESOLVER))
            .build();

    Report report;
    try {
      report = inspector.run(statusListResource);
    } catch (RuntimeException e) {
      return statusListUnreadable(statusListCredentialUrl);
    }
    // The status list's own report is summarized in one item of this probe: its probe names
    // (CredentialParseProbe, EmbeddedProofProbe...) would read as findings about the credential.
    if (report.getOutcome() == Outcome.EXCEPTION) {
      return statusListUnreadable(statusListCredentialUrl);
    }
    if (report.getOutcome() != Outcome.VALID && report.getOutcome() != Outcome.WARNING) {
      return error(
          "The status list credential at " + statusListCredentialUrl + " is not valid", ctx);
    }

    Optional<VerifiableCredential> statusListCredentialMaybe =
        report.getGeneratedObject(VerifiableCredential.ID);
    if (statusListCredentialMaybe.isEmpty()) {
      return statusListUnreadable(statusListCredentialUrl);
    }
    VerifiableCredential statusListCredential = statusListCredentialMaybe.get();

    // 5. Verify that the status purpose is equal to a statusPurpose value in the
    // statusListCredential.
    JsonNode credentialSubject = statusListCredential.getJson().get("credentialSubject");
    if (credentialSubject == null
        || !credentialSubject.hasNonNull("statusPurpose")
        || !credentialSubject.hasNonNull("encodedList")) {
      return error(
          "The status list credential at " + statusListCredentialUrl + " is not valid", ctx);
    }
    String listStatusPurpose = credentialSubject.get("statusPurpose").asText().strip();
    if (!listStatusPurpose.equals(statusPurpose)) {
      return error(
          "statusPurpose mismatch (credential: "
              + statusPurpose
              + ", bitstringStatusListCredential: "
              + listStatusPurpose
              + ")",
          ctx);
    }

    // 6. Let compressed bitstring be the value of the encodedList property of the
    // BitstringStatusListCredential.
    String encodedList = credentialSubject.get("encodedList").asText();
    if (encodedList.isEmpty()) {
      return error("encodedList is empty", ctx);
    }

    // 8. Generate a revocation bitstring by passing compressed bitstring to the Bitstring Expansion
    // Algorithm.
    long index = credentialIndex * statusSize;
    try {
      Expansion expansion = expandAt(encodedList, index);

      // 9. If the length of the revocation bitstring divided by statusSize is less than
      // minimumNumberOfEntries, raise a STATUS_LIST_LENGTH_ERROR.
      if ((expansion.length() * 8L / statusSize) < minimumNumberOfEntries) {
        return error("revocation bitstring length is less than minimumNumberOfEntries", ctx);
      }

      // 10. Let status be the value in the bitstring at the position indicated by the
      // credentialIndex multiplied by the size. If the credentialIndex multiplied by the size is a
      // value outside of the range of the bitstring, a RANGE_ERROR MUST be raised.
      if (expansion.byteAtIndex() < 0) {
        return error(
            "credentialIndex multiplied by the size is a value outside of the range of the"
                + " bitstring",
            ctx);
      }
      int bitPosition = (int) (index % 8); // Find the bit within the byte
      int byteValue = expansion.byteAtIndex();

      // Calculate the mask for the bit we are interested in
      int bitMask = 1 << (7 - bitPosition); // Left-to-right indexing (MSB is 0th bit)
      // Check if the bit is set (non-zero value)
      if ((byteValue & bitMask) != 0) {
        return fatal("Credential has been revoked", ctx);
      }
      return success("Credential is not revoked.", ctx);

    } catch (IOException | RuntimeException e) {
      // RuntimeException: the multibase decoder rejects malformed text with unchecked exceptions.
      return fatal("Error expanding bitstring: " + e.getLocalizedMessage(), ctx);
    }
  }

  /**
   * Reports a status list that could not be downloaded or read. The message names the URL the
   * credential declares, never the rewritten one, which is internal to the deployment.
   */
  private ReportItems statusListUnreadable(URI declaredUrl) {
    return exception(
        "Could not process the status list credential at " + declaredUrl,
        new UriResource(declaredUrl, null, STATUS_LIST_TYPES));
  }

  /**
   * Reads {@code statusListIndex}, which the spec defines as a string holding a base-10 integer;
   * an integer number is accepted as well. Jackson's {@code asInt()} would turn text that is not a
   * number, or one that overflows, into 0 and check the first entry of the list instead.
   *
   * @param node the {@code statusListIndex} value, or {@code null}
   * @return the index, or -1 if it is missing, negative or not an integer of at most 18 digits
   */
  static long statusListIndex(JsonNode node) {
    if (node == null || !(node.isTextual() || node.isIntegralNumber())) {
      return -1;
    }
    String text = node.asText().strip();
    if (!DECIMAL_INDEX.matcher(text).matches()) {
      return -1;
    }
    return Long.parseLong(text);
  }

  private static final Pattern DECIMAL_INDEX = Pattern.compile("[0-9]{1,18}");

  /**
   * The length of an expanded bitstring and the byte that holds a given bit.
   *
   * @param length the number of bytes of the expanded bitstring
   * @param byteAtIndex the unsigned byte that holds the bit, or -1 if the bit is outside the
   *     bitstring
   */
  record Expansion(long length, int byteAtIndex) {}

  /**
   * Multibase-decodes and expands {@code encodedList} with GZIP [RFC1952] (step 2 of the Bitstring
   * Expansion Algorithm), reading the expanded bytes as a stream: only the byte that holds {@code
   * bitIndex} is kept, so memory does not grow with the size of the list.
   *
   * @param encodedList the {@code encodedList} of the status list credential
   * @param bitIndex the position of the first bit of the status entry
   * @return the expanded length and the byte that holds {@code bitIndex}
   * @throws IOException if the text is not valid GZIP or expands beyond {@link
   *     #MAX_EXPANDED_BYTES}
   */
  static Expansion expandAt(String encodedList, long bitIndex) throws IOException {
    byte[] decodedBitstring = MultibaseDecoder.getInstance().decode(encodedList);
    long wantedByte = bitIndex / 8;
    int byteAtIndex = -1;
    long length = 0;
    try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(decodedBitstring))) {
      byte[] buffer = new byte[8192];
      int bytesRead;
      while ((bytesRead = gzip.read(buffer)) != -1) {
        if (length + bytesRead > MAX_EXPANDED_BYTES) {
          throw new IOException("expanded bitstring exceeds " + MAX_EXPANDED_BYTES + " bytes");
        }
        if (wantedByte >= length && wantedByte < length + bytesRead) {
          byteAtIndex = buffer[(int) (wantedByte - length)] & 0xff;
        }
        length += bytesRead;
      }
    }
    return new Expansion(length, byteAtIndex);
  }

  /**
   * Upper bound for an expanded status list. The spec minimum is 131,072 entries (16 KiB at one
   * bit each); this leaves room for large lists and multi-bit entries while keeping a compressed
   * payload from expanding without limit. The expansion is read as a stream, so the bound limits
   * CPU time, not memory.
   */
  static final int MAX_EXPANDED_BYTES = 16 * 1024 * 1024;

  /**
   * Upper bound for the downloaded status list credential. A list of the spec minimum size takes a
   * few hundred bytes once compressed, and the Tec's lists about 16 KiB; the bound keeps a list
   * signed by anyone from filling the heap while it is parsed and its proof is verified.
   */
  static final int MAX_STATUS_LIST_BYTES = 2 * 1024 * 1024;

  static final List<ResourceType> STATUS_LIST_TYPES =
      List.of(
          ResourceType.JSON,
          ResourceType.JSON_LD,
          ResourceType.JWT,
          ResourceType.VC_JSON_LD,
          ResourceType.VC_JWT);

  public static final String ID = BitstringStatusListProbe.class.getSimpleName();
  public static final String TITLE = "Bitstring Status List Validation";
}
