package com.alphawallet.attestation.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class NonceTest {
  private static final String RECEIVER = "www.somewhere.com";
  private static final long TIMESTAMP = 1614693814000L;

  private static SecureRandom rand;
  private static String address;

  @BeforeAll
  public static void setup() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    AsymmetricKeyParameter key = SignatureUtility.constructECKeys(rand).getPublic();
    address = SignatureUtility.addressFromKey(key);
  }

  @Test
  public void retrieveTimestamp() {
    byte[] nonce = Nonce.makeNonce(address, RECEIVER, TIMESTAMP);
    assertEquals(TIMESTAMP, Nonce.getTimestamp(nonce));
  }


  @Test
  public void timestamp() {
    byte[] nonce = Nonce.makeNonce(address, RECEIVER, TIMESTAMP);
    assertTrue(Nonce.validateNonce(nonce, address, RECEIVER, TIMESTAMP+Nonce.TIMESTAMP_SLACK_MS-1, TIMESTAMP+2*Nonce.TIMESTAMP_SLACK_MS));
    assertFalse(Nonce.validateNonce(nonce, address, RECEIVER, TIMESTAMP+Nonce.TIMESTAMP_SLACK_MS+1, TIMESTAMP+2*Nonce.TIMESTAMP_SLACK_MS));
    assertFalse(Nonce.validateNonce(nonce, address, RECEIVER, TIMESTAMP-2*Nonce.TIMESTAMP_SLACK_MS, TIMESTAMP-Nonce.TIMESTAMP_SLACK_MS-1));

  }

  @Test
  public void invalidAddress() {
    AsymmetricKeyParameter key = SignatureUtility.constructECKeys(rand).getPublic();
    String address = SignatureUtility.addressFromKey(key);
    Exception e = assertThrows(IllegalArgumentException.class, () -> Nonce.makeNonce(address+"a", RECEIVER, TIMESTAMP));
    assertEquals(e.getMessage(), "Address is not valid");
  }

  @Test
  public void invalidAddressInValidation() {
    byte[] nonce = Nonce.makeNonce(address, RECEIVER, TIMESTAMP);
    AsymmetricKeyParameter key = SignatureUtility.constructECKeys(rand).getPublic();
    String address = SignatureUtility.addressFromKey(key);
    Exception e = assertThrows(IllegalArgumentException.class, () -> Nonce.validateNonce(nonce, "0"+address, RECEIVER, TIMESTAMP-1, TIMESTAMP+1));
    assertEquals(e.getMessage(), "Address is not valid");
  }

  @Test
  public void otherDataValidation() {
    byte[] otherData = new byte[] {0x42, 0x43};
    byte[] nonce = Nonce.makeNonce(address, RECEIVER, TIMESTAMP, otherData);
    assertTrue(Nonce.validateNonce(nonce, address, RECEIVER, TIMESTAMP-1, TIMESTAMP+1, otherData));
    otherData[0] ^= 0x01;
    assertFalse(Nonce.validateNonce(nonce, address, RECEIVER, TIMESTAMP-1, TIMESTAMP+1, otherData));
  }

  @Test
  public void keyValidation() {
    byte[] nonce = Nonce.makeNonce(address, RECEIVER, TIMESTAMP);
    assertTrue(Nonce.validateNonce(nonce, address, RECEIVER, TIMESTAMP-1, TIMESTAMP+1));
    AsymmetricKeyParameter otherKey = SignatureUtility.constructECKeys(rand).getPublic();
    String otherAddress = SignatureUtility.addressFromKey(otherKey);
    assertFalse(Nonce.validateNonce(nonce, otherAddress, RECEIVER, TIMESTAMP-1, TIMESTAMP+1));
  }


  @Test
  public void validateReceiverIdentifier() {
    byte[] nonce = Nonce.makeNonce(address, RECEIVER, TIMESTAMP);
    assertTrue(Nonce.validateNonce(nonce, address, RECEIVER, TIMESTAMP-1, TIMESTAMP+1));
    assertFalse(Nonce.validateNonce(nonce, address, "wrongReceiver", TIMESTAMP-1, TIMESTAMP+1));
  }

}
