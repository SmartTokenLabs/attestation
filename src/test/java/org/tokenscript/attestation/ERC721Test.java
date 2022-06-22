package org.tokenscript.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class ERC721Test {
  private static final String validAddress = "0x01020304050607080910111213141516171819ff";
  private static final BigInteger validTokenId = new BigInteger("1234");

  @Test
  public void sunshine() {
    ERC721Token token = new ERC721Token(validAddress, validTokenId, 42L);
    assertEquals(token.getAddress(), validAddress);
    assertEquals(token.getTokenId(), validTokenId);
    assertEquals(token.getChainId(),42);
  }

  @Test
  public void sunshineDefaultValues() throws IOException {
    ERC721Token token = new ERC721Token(validAddress, 42L);

    ERC721Token decodedToken = new ERC721Token(token.getDerEncoding());
    assertEquals(decodedToken.getAddress(), validAddress);
    assertEquals(decodedToken.getTokenId(), null);
    assertEquals(decodedToken.getChainId(),42);
    assertArrayEquals(token.getDerEncoding(), decodedToken.getDerEncoding());
  }

  @Test
  public void sunshineOtherConstructor() throws IOException {
    ERC721Token token = new ERC721Token(validAddress);
    ERC721Token decodedToken = new ERC721Token(token.getDerEncoding());
    assertEquals(decodedToken.getAddress(), validAddress);
    assertEquals(decodedToken.getTokenId(), null);
    assertEquals(decodedToken.getChainId(), null);
    assertArrayEquals(token.getDerEncoding(), decodedToken.getDerEncoding());
  }

  @Test
  public void consistencyEncoding() throws IOException {
    ERC721Token token = new ERC721Token(validAddress, validTokenId, 42L);
    byte[] tokenEncoding = token.getDerEncoding();
    ERC721Token secondToken = new ERC721Token(token.getDerEncoding());
    byte[] secondTokenEncoding = secondToken.getDerEncoding();
    assertEquals(token.getTokenId(), secondToken.getTokenId());
    assertEquals(token.getAddress(), secondToken.getAddress());
    assertArrayEquals(tokenEncoding, secondTokenEncoding);
  }

  @Test
  public void addressNormalizedToLowerCase() {
    // Ensure that the address is normalized
    ERC721Token token = new ERC721Token("01020304050607080910111213141516171819FF", "1234");
    assertEquals(token.getAddress(), validAddress);
  }

  @Test
  public void onlyPositiveIds() {
    assertThrows(IllegalArgumentException.class, ()-> new ERC721Token(validAddress, "-100"));
  }

  @Test
  public void addressTooLong() {
    assertThrows(IllegalArgumentException.class, ()-> new ERC721Token(validAddress+"1234", "-100"));
  }

  @Test
  public void failOnWrongId() {
    assertThrows(IllegalArgumentException.class, ()-> new ERC721Token(validAddress, "notANumber"));
  }
}
