package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class ValidationToolsTest {
  @Test
  public void testNullAddress() {
    assertThrows(NullPointerException.class, () -> ValidationTools.isAddress(null));
    assertTrue(ValidationTools.isNullOrAddress(null));
  }

  @Test
  public void testAddress() {
    assertTrue(ValidationTools.isAddress("0x0123456789012345678901234567890123456789"));
    assertTrue(ValidationTools.isAddress("0x01234567890123456789012345678901234567Ff"));
  }

  @Test
  public void negativeAddress() {
    // Too long
    assertFalse(ValidationTools.isAddress("0x01234567890123456789012345678901234567890"));
    // Too short
    assertFalse(ValidationTools.isAddress("0x012345678901234567890123456789012345678"));
    // Wrong prefix
    assertFalse(ValidationTools.isAddress("0Y0123456789012345678901234567890123456789"));
    // Wrong character
    assertFalse(ValidationTools.isAddress("0x012345678901234567890123456789012345678G"));
  }

}
