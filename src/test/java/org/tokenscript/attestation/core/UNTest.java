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

    // Generate keys
    AsymmetricCipherKeyPair keys = SignatureUtility.constructECKeysWithSmallestY(rand);
    FileImportExport.storePrivKey(keys.getPrivate(), "un-priv.pem");
    FileImportExport.storePubKey(keys.getPublic(), "un-pub.pem");
    AsymmetricCipherKeyPair otherKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    FileImportExport.storePrivKey(otherKeys.getPrivate(), "other-priv.pem");
    FileImportExport.storePubKey(otherKeys.getPublic(), "other-pub.pem");
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

  @Test
  void makeExportableSigUn() throws Exception {
    AsymmetricCipherKeyPair keys = FileImportExport.loadPrivKey("un-priv.pem");
    UnpredictableNumberTool unt = new UNSignature(rand, keys, DOMAIN,
        1000L * 365L * 24L * 3600L * 1000L);
    UnpredictableNumberBundle unb = unt.getUnpredictableNumberBundle(new byte[]{42});
    assertTrue(unt.validateUnpredictableNumber(unb.getNumber(), unb.getRandomness(),
        unb.getExpiration(), new byte[]{42}));
  }

  @Test
  void makeExportableMacUn() {
    UnpredictableNumberTool unt = new UNMac(rand, macKey, DOMAIN,
        1000L * 365L * 24L * 3600L * 1000L);
    UnpredictableNumberBundle unb = unt.getUnpredictableNumberBundle(new byte[]{42});
    assertTrue(unt.validateUnpredictableNumber(unb.getNumber(), unb.getRandomness(),
        unb.getExpiration(), new byte[]{42}));
  }

  @Test
  void validateJSMacGeneration() {
    String un = "x-o_7_ppapx--UpwQAFtYA==";
    byte[] randomness = new byte[]{100, 98, 187 - 256, 18, 244 - 256, 230 - 256, 175 - 256, 62, 26,
        210 - 256, 38, 251 - 256, 7, 222 - 256
        , 50, 33, 191 - 256, 155 - 256, 215 - 256, 163 - 256, 142 - 256, 70, 37, 88, 236 - 256,
        148 - 256, 84, 159 - 256, 188 - 256, 45, 208 - 256, 227 - 256};
    long expiration = 33198027294505L;
    UNMac unMac = new UNMac(macKey, DOMAIN);
    assertTrue(unMac.validateUnpredictableNumber(un, randomness, expiration));
  }

  @Test
  void validateJSSigGeneration() throws Exception {
    String un = "yYLsRm9nfOvgbka-4l1jPT6hZUqlWMXMPTT2oNNwdVofKfSO3KHlaTbAA3f3nFYD3RzjJnKn2HAHOTIYbg89ZRs=";
    byte[] randomness = new byte[]{134 - 256, 31, 150 - 256, 186 - 256, 8, 186 - 256, 160 - 256,
        249 - 256, 168 - 256, 85, 213 - 256, 242 - 256, 60,
        23, 39, 224 - 256, 62, 66, 72, 103, 247 - 256, 109, 189 - 256, 148 - 256, 197 - 256,
        222 - 256, 92, 246 - 256, 21, 248 - 256,
        107, 206 - 256};
    long expiration = 33198032422216L;
    AsymmetricKeyParameter validationKey = FileImportExport.loadPubKey("un-pub.pem");
    UNSignature unSig = new UNSignature(validationKey, DOMAIN);
    assertTrue(unSig.validateUnpredictableNumber(un, randomness, expiration));
  }

  @Test
  void validateJSMacGenerationWContext() {
    String un = "J1QI1QZE68m4U8-90o3OVA==";
    byte[] randomness = new byte[]{217 - 256, 148 - 256, 187 - 256, 152 - 256, 56, 217 - 256,
        226 - 256, 105, 216 - 256, 65, 233 - 256, 37, 30,
        167 - 256, 136 - 256, 215 - 256, 97, 46, 46, 156 - 256, 193 - 256, 180 - 256, 89, 219 - 256,
        173 - 256, 217 - 256, 70, 184 - 256, 195 - 256, 38, 180 - 256, 251 - 256};
    long expiration = 33198031941306L;
    UNMac unMac = new UNMac(macKey, DOMAIN);
    assertTrue(unMac.validateUnpredictableNumber(un, randomness, expiration));
  }

  @Test
  void validateJSSigGenerationWContext() throws Exception {
    String un = "5jv9yXAV04-NYukTVEB3IDSdRTH5vqw_LUWRmm5PYyojqA3o72z2xNdGlfO1wfs1SSIMx7IxhqmE9ALECp37Lxs=";
    byte[] randomness = new byte[]{187 - 256, 91, 75, 58, 122, 20, 38, 223 - 256, 231 - 256,
        200 - 256, 8, 101, 210 - 256, 97,
        108, 119, 82, 8, 156 - 256, 168 - 256, 205 - 256, 64, 181 - 256, 245 - 256, 134 - 256,
        198 - 256, 174 - 256, 161 - 256, 203 - 256, 50, 141 - 256, 57};
    long expiration = 33198032192922L;
    AsymmetricKeyParameter validationKey = FileImportExport.loadPubKey("un-pub.pem");
    UNSignature unSig = new UNSignature(validationKey, DOMAIN);
    assertTrue(unSig.validateUnpredictableNumber(un, randomness, expiration));
  }
}
