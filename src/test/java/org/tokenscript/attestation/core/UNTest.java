package org.tokenscript.attestation.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class UNTest {
  private static final String DOMAIN = "http://www.hotel-bogota.com";
  private static byte[] macKey;
  private static SecureRandom rand;
  private static AsymmetricCipherKeyPair keys;

  @Mock
  UnpredictableNumberBundle mockedUn;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    macKey = rand.generateSeed(16);
    keys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

  @BeforeEach
  public void makeUn() {
    MockitoAnnotations.openMocks(this);

    Mockito.when(mockedUn.getDomain()).thenReturn(DOMAIN);
    Mockito.when(mockedUn.getExpiration()).thenReturn(Long.MAX_VALUE);
    Mockito.when(mockedUn.getRandomness()).thenReturn(new byte[UnpredictableNumberTool.BYTES_IN_SEED]);
    Mockito.when(mockedUn.getNumber()).thenReturn("abcdefghijk");
  }

  @Test
  void sunshine() {
    sunshineTest(new UNMac(macKey, DOMAIN));
    sunshineTest(new UNSignature(keys, DOMAIN));
  }

  void sunshineTest(UnpredictableNumberTool un) {
    assertEquals(DOMAIN, un.getDomain());
    UnpredictableNumberBundle unb = un.getUnpredictableNumberBundle();
    assertTrue(un.validateUnpredictableNumber(unb.getNumber(), unb.getRandomness(), unb.getExpiration()));
  }

  @Test
  void contextOptional() throws Exception {
    contextOptionalTest(new UNMac(macKey, DOMAIN));
    contextOptionalTest(new UNSignature(keys, DOMAIN));
  }

  void contextOptionalTest(UnpredictableNumberTool un) throws Exception {
    ObjectMapper jsonMapper = new ObjectMapper();

    UnpredictableNumberBundle unb = un.getUnpredictableNumberBundle();
    String jsonEncoding = jsonMapper.writeValueAsString(unb);
    assertFalse(jsonEncoding.contains("context"));
    UnpredictableNumberBundle unbWContext = un.getUnpredictableNumberBundle(new byte[]{0x42});
    String jsonEncodingWContext = jsonMapper.writeValueAsString(unbWContext);
    assertTrue(jsonEncodingWContext.contains("context"));
  }

  @Test
  void invalidDomainMAC() {
    assertThrows(IllegalArgumentException.class, () -> new UNMac(macKey, "NotaDomain"));
  }

  @Test
  void invalidDomainSig() {
    assertThrows(IllegalArgumentException.class, () -> new UNSignature(keys, "NotaDomain"));
  }

  @Test
  void expired() {
    expiredTest(new UNMac(macKey, DOMAIN));
    expiredTest(new UNSignature(keys, DOMAIN));
  }

  void expiredTest(UnpredictableNumberTool un) {
    // expired jan 1, 1970
    Mockito.when(mockedUn.getExpiration()).thenReturn(0L);
    assertFalse(un.validateUnpredictableNumber(mockedUn.getNumber(), mockedUn.getRandomness(), mockedUn.getExpiration()));
  }

  @Test
  void wrongUn() {
    wrongUnTest(new UNMac(macKey, DOMAIN), new UNMac(macKey, "http://www.other-domain.com"), new UNMac(rand.generateSeed(16), DOMAIN));
    wrongUnTest(new UNSignature(keys, DOMAIN), new UNSignature(keys, "http://www.other-domain.com"), new UNSignature(SignatureUtility.constructECKeysWithSmallestY(rand), DOMAIN));
  }

  void wrongUnTest(UnpredictableNumberTool un, UnpredictableNumberTool wrongUn, UnpredictableNumberTool otherWrongUn) {
    UnpredictableNumberBundle unb = un.getUnpredictableNumberBundle();
    assertTrue(un.validateUnpredictableNumber(unb.getNumber(), unb.getRandomness(), unb.getExpiration()));
    assertFalse(wrongUn.validateUnpredictableNumber(unb.getNumber(), mockedUn.getRandomness(), unb.getExpiration()));
    assertFalse(otherWrongUn.validateUnpredictableNumber(unb.getNumber(), mockedUn.getRandomness(), unb.getExpiration()));
  }
}
