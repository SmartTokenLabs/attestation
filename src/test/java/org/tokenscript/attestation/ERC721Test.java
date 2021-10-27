package org.tokenscript.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

public class ERC721Test {

  @Test
  public void sunshine() {
    ERC721Token token = new ERC721Token("deadbeef", "1234");
    assertEquals(token.getAddress(), "deadbeef");
    assertEquals(token.getTokenId(), new BigInteger("1234"));
  }

  @Test
  public void sunshineBigIntegerId() {
    ERC721Token token = new ERC721Token("deadbeef", new BigInteger("1234"));
    assertEquals(token.getAddress(), "deadbeef");
    assertEquals(token.getTokenId(), new BigInteger("1234"));
  }

  @Test
  public void consistencyEncoding() throws IOException {
    ERC721Token token = new ERC721Token("DEADBEEF", "1234");
    byte[] tokenEncoding = token.getDerEncoding();
    ERC721Token secondToken = new ERC721Token(token.getDerEncoding());
    byte[] secondTokenEncoding = secondToken.getDerEncoding();
    assertEquals(token.getTokenId(), secondToken.getTokenId());
    assertEquals(token.getAddress(), secondToken.getAddress());
    assertArrayEquals(tokenEncoding, secondTokenEncoding);
  }

  @Test
  public void addressNormalizedToLowerCase() {
    ERC721Token token = new ERC721Token("DEADBEEF", "1234");
    assertEquals(token.getAddress(), "deadbeef");
  }

  @Test
  public void onlyPositiveIds() {
    assertThrows(IllegalArgumentException.class, ()-> new ERC721Token("DEADBEAF", "-100"));
  }

  @Test
  public void wrongIdBecomesZero() {
    ERC721Token token = new ERC721Token("DEADBEEF", "notANumber");
    assertEquals(token.getTokenId(), BigInteger.ZERO);
  }
}
