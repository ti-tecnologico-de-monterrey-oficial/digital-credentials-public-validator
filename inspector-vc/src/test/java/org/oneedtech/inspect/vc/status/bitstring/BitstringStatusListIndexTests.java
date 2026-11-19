package org.oneedtech.inspect.vc.status.bitstring;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

public class BitstringStatusListIndexTests {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private static JsonNode json(String value) throws Exception {
    return MAPPER.readTree(value);
  }

  @Test
  void readsDecimalStringsAndIntegers() throws Exception {
    assertEquals(304, BitstringStatusListProbe.statusListIndex(json("\"304\"")));
    assertEquals(0, BitstringStatusListProbe.statusListIndex(json("\"0\"")));
    assertEquals(304, BitstringStatusListProbe.statusListIndex(json("304")));
    assertEquals(
        2_147_483_648L, BitstringStatusListProbe.statusListIndex(json("\"2147483648\"")));
  }

  @Test
  void rejectsWhatIsNotANonNegativeInteger() {
    assertAll(
        Stream.of("\"abc\"", "\"-1\"", "-1", "\"1.5\"", "1.5", "\"\"", "\"1e3\"", "null", "true",
                "\"9999999999999999999\"", "[1]")
            .map(
                value ->
                    () ->
                        assertEquals(
                            -1, BitstringStatusListProbe.statusListIndex(json(value)), value)));
    assertEquals(-1, BitstringStatusListProbe.statusListIndex(null));
  }
}
