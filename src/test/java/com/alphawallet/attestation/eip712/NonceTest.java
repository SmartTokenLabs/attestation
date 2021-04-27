package com.alphawallet.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.core.SignatureUtility;
import java.security.SecureRandom;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class NonceTest {
  private static final String RECEIVER = "www.somewhere.com";
  private static final Timestamp TIMESTAMP = new Timestamp();
  private static final Timestamp MIN_TIMESTAMP = new Timestamp(TIMESTAMP.getTime()-2000);
  private static final Timestamp MAX_TIMESTAMP = new Timestamp(TIMESTAMP.getTime()+2000);

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
    assertEquals(TIMESTAMP.getTime(), Nonce.getTimestamp(nonce).getTime());
  }

  @Test
  public void timestamp() {
    byte[] nonce = Nonce.makeNonce(address, RECEIVER, TIMESTAMP);
    assertFalse(Nonce.validateNonce(nonce, address, RECEIVER, MAX_TIMESTAMP, MIN_TIMESTAMP));
    assertFalse(Nonce.validateNonce(nonce, address, RECEIVER, MIN_TIMESTAMP, MIN_TIMESTAMP));
    assertFalse(Nonce.validateNonce(nonce, address, RECEIVER, MAX_TIMESTAMP, MAX_TIMESTAMP));
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
    Exception e = assertThrows(IllegalArgumentException.class, () -> Nonce.validateNonce(nonce, "0"+address, RECEIVER, MIN_TIMESTAMP, MAX_TIMESTAMP));
    assertEquals(e.getMessage(), "Address is not valid");
  }

  @Test
  public void otherDataValidation() {
    byte[] otherData = new byte[] {0x42, 0x43};
    byte[] nonce = Nonce.makeNonce(address, RECEIVER, TIMESTAMP, otherData);
    assertTrue(Nonce.validateNonce(nonce, address, RECEIVER, MIN_TIMESTAMP, MAX_TIMESTAMP, otherData));
    otherData[0] ^= 0x01;
    assertFalse(Nonce.validateNonce(nonce, address, RECEIVER, MIN_TIMESTAMP, MAX_TIMESTAMP, otherData));
  }

  @Test
  public void keyValidation() {
    byte[] nonce = Nonce.makeNonce(address, RECEIVER, TIMESTAMP);
    assertTrue(Nonce.validateNonce(nonce, address, RECEIVER, MIN_TIMESTAMP, MAX_TIMESTAMP));
    AsymmetricKeyParameter otherKey = SignatureUtility.constructECKeys(rand).getPublic();
    String otherAddress = SignatureUtility.addressFromKey(otherKey);
    assertFalse(Nonce.validateNonce(nonce, otherAddress, RECEIVER, MIN_TIMESTAMP, MAX_TIMESTAMP));
  }


  @Test
  public void validateReceiverIdentifier() {
    byte[] nonce = Nonce.makeNonce(address, RECEIVER, TIMESTAMP);
    assertTrue(Nonce.validateNonce(nonce, address, RECEIVER, MIN_TIMESTAMP, MAX_TIMESTAMP));
    assertFalse(Nonce.validateNonce(nonce, address, "wrongReceiver", MIN_TIMESTAMP, MAX_TIMESTAMP));
  }

}
