package org.oneedtech.inspect.vc.status.bitstring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;

public class BitstringStatusListExpansionTests {

  /** Compresses with GZIP and encodes as multibase base64url without padding (prefix {@code u}). */
  private static String encode(byte[] bitstring) throws IOException {
    ByteArrayOutputStream compressed = new ByteArrayOutputStream();
    try (GZIPOutputStream gzip = new GZIPOutputStream(compressed)) {
      gzip.write(bitstring);
    }
    return "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(compressed.toByteArray());
  }

  @Test
  void readsTheLengthAndTheByteThatHoldsTheIndex() throws IOException {
    byte[] bitstring = new byte[16 * 1024];
    bitstring[3] = (byte) 0x80;
    BitstringStatusListProbe.Expansion expansion =
        BitstringStatusListProbe.expandAt(encode(bitstring), 3 * 8);
    assertEquals(16 * 1024, expansion.length());
    assertEquals(0x80, expansion.byteAtIndex());
    assertEquals(0, BitstringStatusListProbe.expandAt(encode(bitstring), 4 * 8).byteAtIndex());
  }

  @Test
  void reportsAnIndexOutsideTheBitstring() throws IOException {
    BitstringStatusListProbe.Expansion expansion =
        BitstringStatusListProbe.expandAt(encode(new byte[16]), 16 * 8);
    assertEquals(16, expansion.length());
    assertEquals(-1, expansion.byteAtIndex());
  }

  @Test
  void rejectsAListThatExpandsBeyondTheLimit() throws IOException {
    String bomb = encode(new byte[BitstringStatusListProbe.MAX_EXPANDED_BYTES + 1]);
    assertThrows(IOException.class, () -> BitstringStatusListProbe.expandAt(bomb, 0));
  }
}
