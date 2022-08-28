package org.tokenscript.attestation.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

public class UNTest {

  private static final String DOMAIN = "http://www.hotel-bogota.com";
  private static final byte[] macKey = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
      , 16};
  private static SecureRandom rand;
  private static AsymmetricCipherKeyPair keys;

  @Mock
  UnpredictableNumberBundle mockedUn;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());

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
    wrongUnTest(new UNMac(macKey, DOMAIN), new UNMac(macKey, "http://www.other-domain.com"),
        new UNMac(rand.generateSeed(16), DOMAIN));
    wrongUnTest(new UNSignature(keys, DOMAIN), new UNSignature(keys, "http://www.other-domain.com"),
        new UNSignature(SignatureUtility.constructECKeysWithSmallestY(rand), DOMAIN));
  }

  void wrongUnTest(UnpredictableNumberTool un, UnpredictableNumberTool wrongUn,
      UnpredictableNumberTool otherWrongUn) {
    UnpredictableNumberBundle unb = un.getUnpredictableNumberBundle();
    assertTrue(
        un.validateUnpredictableNumber(unb.getNumber(), unb.getRandomness(), unb.getExpiration()));
    assertFalse(wrongUn.validateUnpredictableNumber(unb.getNumber(), mockedUn.getRandomness(),
        unb.getExpiration()));
    assertFalse(otherWrongUn.validateUnpredictableNumber(unb.getNumber(), mockedUn.getRandomness(),
        unb.getExpiration()));
  }

  // Test that we can still validate 8 byte UNs
  @Test
  void legacyUN() {
//    UNMac un =  new UNMac(rand, macKey, DOMAIN, 10L*365L*24L*3600L*1000L);
//    UnpredictableNumberBundle unb = un.getUnpredictableNumberBundle();
//    String number = unb.getNumber();
    byte[] randomness = new byte[]{117, -106, -9, 48, 71, 18, -58, 36, -121, 69, 93, 120, -100, 100,
        -108, 104, -5, 67, 73, -36, -121, 79, -128, -128, -59, -119, -2, -86, -126, -36, 74, 117};
    String UN = "ABJ34us29mc=";
    long expiration = 1977060911693L;
    UNMac unMac = new UNMac(macKey, DOMAIN);
    assertTrue(unMac.validateUnpredictableNumber(UN, randomness, expiration));
  }

  @Disabled
  @Test
  void validateJSGeneration() {
    String un = "c1868fc94f7438b6";
    byte[] randomness = new byte[]{256 - 176, 79, 113, 256 - 151, 256 - 207, 108, 54, 75, 53, 43,
        256 - 221, 256 - 204, 47,
        256 - 181, 117, 256 - 171, 46, 103, 56, 89, 63, 17, 256 - 226, 106, 31, 25, 75, 12, 4, 101,
        256 - 185, 107};
    long expiration = 1977062377416L;
    UNMac unMac = new UNMac(macKey, DOMAIN);
    assertTrue(unMac.validateUnpredictableNumber(un, randomness, expiration));
  }
}
