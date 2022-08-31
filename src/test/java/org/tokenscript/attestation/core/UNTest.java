package org.tokenscript.attestation.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.tokenscript.attestation.FileImportExport;

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
    sunshineTest(new UNSignature(rand, keys, DOMAIN, 1000L * 365L * 24L * 3600L * 1000L));
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

  //  @Disabled
  @Test
  void validateJSMacGeneration() {
    String un = "IoIcXB9LCm1S1VN0E80zhg==";
    byte[] randomness = new byte[]{132 - 256, 251 - 256, 245 - 256, 132 - 256, 96, 182 - 256, 49,
        190 - 256, 186 - 256, 156 - 256, 11, 43, 160 - 256,
        73, 77, 130 - 256, 119, 117, 76, 60, 17, 28, 8, 177 - 256, 117, 76, 202 - 256, 26,
        150 - 256, 95, 131 - 256, 126};
    long expiration = 1977137270306L;
    UNMac unMac = new UNMac(macKey, DOMAIN);
    assertTrue(unMac.validateUnpredictableNumber(un, randomness, expiration));
  }

  @Test
  void validateJSSigGeneration() throws Exception {
    String un = "7NA_5MF9HFwVq6hxQxVOU1kOCeSBknpMbogra_1cmEoMae8c8dZkeB45QO9s1UwvQEcLb_o6cyuqA3nJfGl3zBs=";
    byte[] randomness = new byte[]{217 - 256, 141 - 256, 90, 184 - 256, 132 - 256, 214 - 256, 78,
        65, 104, 151 - 256, 25, 111, 175 - 256,
        152 - 256, 92, 43, 154 - 256, 124, 189 - 256, 244 - 256, 246 - 256, 53, 68, 164 - 256,
        242 - 256, 84, 171 - 256, 240 - 256, 1, 107, 158 - 256, 153 - 256};
    long expiration = 1977144050099L;
    AsymmetricKeyParameter validationKey = FileImportExport.loadPubKey("attestor-pub.pem");
    UNSignature unSig = new UNSignature(validationKey, DOMAIN);
    assertTrue(unSig.validateUnpredictableNumber(un, randomness, expiration));
  }

  // Only needs to be run to generate integration test material and requires that attestor-priv
  // .pem has been generated first
  @Disabled
  @Test
  void makeExportableUn() throws Exception {
    AsymmetricCipherKeyPair keys = FileImportExport.loadPrivKey("attestor-priv.pem");
    UnpredictableNumberTool unt = new UNSignature(rand, keys, DOMAIN,
        1000L * 365L * 24L * 3600L * 1000L);
    UnpredictableNumberBundle unb = unt.getUnpredictableNumberBundle();
    assertTrue(unt.validateUnpredictableNumber(unb.getNumber(), unb.getRandomness(),
        unb.getExpiration()));
  }
}
