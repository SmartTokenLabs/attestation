package org.tokenscript.attestation;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ERC721Test {
  private static final String validAddress = "0x01020304050607080910111213141516171819ff";
  private static final BigInteger validTokenId = new BigInteger("1234");

  @Test
  void sunshine() {
    ERC721Token token = new ERC721Token(validAddress, validTokenId, 42L);
    assertEquals(validAddress, token.getAddress());
    assertEquals(List.of(validTokenId), token.getTokenIds());
    assertEquals(42, token.getChainId());
  }

  @Test
  void sunshineDefaultValues() throws IOException {
    ERC721Token token = new ERC721Token(validAddress, 42L);

    ERC721Token decodedToken = new ERC721Token(token.getDerEncoding());
    assertEquals(validAddress, decodedToken.getAddress());
    assertNull(decodedToken.getTokenIds());
    assertEquals(42, decodedToken.getChainId());
    assertArrayEquals(token.getDerEncoding(), decodedToken.getDerEncoding());
  }

  @Test
  void sunshineArrayOfTokenIds() {
    List<BigInteger> tokenIds = Arrays.asList(BigInteger.valueOf(1234), new BigInteger("1234564647891843851486465404"));
    ERC721Token token = new ERC721Token(validAddress, tokenIds, 42L);
    assertEquals(validAddress, token.getAddress());
    assertEquals(tokenIds, token.getTokenIds());
    assertEquals(42, token.getChainId());
  }

  @Test
  void sunshineOtherConstructor() throws IOException {
    ERC721Token token = new ERC721Token(validAddress);
    ERC721Token decodedToken = new ERC721Token(token.getDerEncoding());
    assertEquals(validAddress, decodedToken.getAddress());
    assertNull(decodedToken.getTokenIds());
    assertEquals(ERC721Token.DEFAULT_CHAIN_ID, decodedToken.getChainId());
    assertArrayEquals(token.getDerEncoding(), decodedToken.getDerEncoding());
  }

  @Test
  void sunshineThirdConstructor() {
    ERC721Token token = new ERC721Token(validAddress, validTokenId);
    assertEquals(validAddress, token.getAddress());
    assertEquals(List.of(validTokenId), token.getTokenIds());
    assertEquals(ERC721Token.DEFAULT_CHAIN_ID, token.getChainId());
  }

  @Test
  void consistencyEncoding() throws IOException {
    ERC721Token token = new ERC721Token(validAddress, validTokenId, 42L);
    byte[] tokenEncoding = token.getDerEncoding();
    ERC721Token secondToken = new ERC721Token(token.getDerEncoding());
    byte[] secondTokenEncoding = secondToken.getDerEncoding();
    assertEquals(token.getTokenIds(), secondToken.getTokenIds());
    assertEquals(token.getAddress(), secondToken.getAddress());
    assertArrayEquals(tokenEncoding, secondTokenEncoding);
  }

  @Test
  void consistencyEncodingArraysOfIds() throws IOException {
    List<BigInteger> tokenIds = Arrays.asList(BigInteger.valueOf(1234), new BigInteger("1234564647891843851486465404"));
    ERC721Token token = new ERC721Token(validAddress, tokenIds, 42L);
    byte[] tokenEncoding = token.getDerEncoding();
    ERC721Token secondToken = new ERC721Token(token.getDerEncoding());
    byte[] secondTokenEncoding = secondToken.getDerEncoding();
    assertEquals(token.getTokenIds(), secondToken.getTokenIds());
    assertEquals(token.getAddress(), secondToken.getAddress());
    assertArrayEquals(tokenEncoding, secondTokenEncoding);
  }

  @Test
  void addressNormalizedToLowerCase() {
    // Ensure that the address is normalized
    ERC721Token token = new ERC721Token("01020304050607080910111213141516171819FF", "1234");
    assertEquals(validAddress, token.getAddress());
  }

  @Test
  void onlyPositiveIds() {
    ERC721Token token = new ERC721Token(validAddress, "-100");
    assertFalse(token.checkValidity());
  }

  @Test
  void addressTooLong() {
    ERC721Token token = new ERC721Token(validAddress + "1234", "-100");
    assertFalse(token.checkValidity());
  }

  @Test
  void failOnWrongId() {
    assertThrows(IllegalArgumentException.class, () -> new ERC721Token(validAddress, "notANumber"));
  }

  @Test
  void wrongChainId() {
    ERC721Token badChain = new ERC721Token(validAddress, validTokenId, -1L);
    assertFalse(badChain.checkValidity());
  }

  @Test
  void tooBigId() {
    ERC721Token badChain = new ERC721Token(validAddress, BigInteger.valueOf(2).pow(256).add(BigInteger.ONE));
    assertFalse(badChain.checkValidity());
  }
}
