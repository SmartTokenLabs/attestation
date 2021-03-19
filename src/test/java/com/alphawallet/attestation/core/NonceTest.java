package com.alphawallet.attestation.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.time.Clock;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class NonceTest {
  private static final String USER = "someone@somewhere.something";
  private static final String RECEIVER = "www.somewhere.com";
  private static final long TIMESTAMP = 1614693814000L;
  private static final long TIMESTAMP_SLACK_MS = 1000*60; // 1 min

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
    byte[] nonce = Nonce.makeNonce(USER, address, RECEIVER, TIMESTAMP);
    assertEquals(TIMESTAMP, Nonce.getTimestamp(nonce));
  }

  @Test
  public void validateTimestamp() {
    long currentTime;
    currentTime = TIMESTAMP + 1000;
    assertTrue(Nonce.validateTimestamp(TIMESTAMP, currentTime, TIMESTAMP_SLACK_MS));
    currentTime = TIMESTAMP - 1000;
    assertTrue(Nonce.validateTimestamp(TIMESTAMP, currentTime, TIMESTAMP_SLACK_MS));
  }

  @Test
  public void invalidTimestamp() {
    long currentTime;
    currentTime = TIMESTAMP + TIMESTAMP_SLACK_MS + 1000;
    assertFalse(Nonce.validateTimestamp(TIMESTAMP, currentTime, TIMESTAMP_SLACK_MS));
    currentTime = TIMESTAMP - TIMESTAMP_SLACK_MS - 1000;
    assertFalse(Nonce.validateTimestamp(TIMESTAMP, currentTime, TIMESTAMP_SLACK_MS));
  }

  @Test
  public void invalidTimestampInValidation() {
    byte[] nonce = Nonce.makeNonce(USER, address, RECEIVER, TIMESTAMP);
    assertFalse(Nonce.validateNonce(nonce, USER, address, RECEIVER, TIMESTAMP_SLACK_MS));
  }

  @Test
  public void invalidAddress() {
    long currentTime = Clock.systemUTC().millis();
    AsymmetricKeyParameter key = SignatureUtility.constructECKeys(rand).getPublic();
    String address = SignatureUtility.addressFromKey(key);
    assertThrows(UnsupportedOperationException.class, () -> Nonce.makeNonce(USER, address+"a", RECEIVER, currentTime));
  }

  @Test
  public void invalidAddressInValidation() {
    long currentTime = Clock.systemUTC().millis();
    byte[] nonce = Nonce.makeNonce(USER, address, RECEIVER, currentTime);
    AsymmetricKeyParameter key = SignatureUtility.constructECKeys(rand).getPublic();
    String address = SignatureUtility.addressFromKey(key);
    assertThrows(NumberFormatException.class, () -> Nonce.validateNonce(nonce, USER, "0"+address, RECEIVER, TIMESTAMP_SLACK_MS));
  }

  @Test
  public void otherDataValidation() {
    long currentTime = Clock.systemUTC().millis();
    byte[] otherData = new byte[] {0x42, 0x43};
    byte[] nonce = Nonce.makeNonce(USER, address, RECEIVER, otherData, currentTime);
    assertTrue(Nonce.validateNonce(nonce, USER, address, RECEIVER, TIMESTAMP_SLACK_MS, otherData));
    otherData[0] ^= 0x01;
    assertFalse(Nonce.validateNonce(nonce, USER, address, RECEIVER, TIMESTAMP_SLACK_MS, otherData));
  }

  @Test
  public void senderValidation() {
    long currentTime = Clock.systemUTC().millis();
    byte[] nonce = Nonce.makeNonce(USER, address, RECEIVER, currentTime);
    assertTrue(Nonce.validateNonce(nonce, USER, address, RECEIVER, TIMESTAMP_SLACK_MS));
    assertFalse(Nonce.validateNonce(nonce, "wrongIdentifier", address, RECEIVER, TIMESTAMP_SLACK_MS));
  }

  @Test
  public void keyValidation() {
    long currentTime = Clock.systemUTC().millis();
    byte[] nonce = Nonce.makeNonce(USER, address, RECEIVER, currentTime);
    assertTrue(Nonce.validateNonce(nonce, USER, address, RECEIVER, TIMESTAMP_SLACK_MS));
    AsymmetricKeyParameter otherKey = SignatureUtility.constructECKeys(rand).getPublic();
    String otherAddress = SignatureUtility.addressFromKey(otherKey);
    assertFalse(Nonce.validateNonce(nonce, USER, otherAddress, RECEIVER, TIMESTAMP_SLACK_MS));
  }


  @Test
  public void validateReceiverIdentifier() {
    long currentTime = Clock.systemUTC().millis();
    byte[] nonce = Nonce.makeNonce(USER, address, RECEIVER, currentTime);
    assertTrue(Nonce.validateNonce(nonce, USER, address, RECEIVER, TIMESTAMP_SLACK_MS));
    assertFalse(Nonce.validateNonce(nonce, USER, address, "wrongReceiver", TIMESTAMP_SLACK_MS));
  }

}
