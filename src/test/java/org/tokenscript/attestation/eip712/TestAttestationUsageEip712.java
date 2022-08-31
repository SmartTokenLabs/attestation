package org.tokenscript.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.tokenscript.attestation.FileImportExport;
import org.tokenscript.attestation.FullProofOfExponent;
import org.tokenscript.attestation.HelperTest;
import org.tokenscript.attestation.IdentifierAttestation;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.SignedIdentifierAttestation;
import org.tokenscript.attestation.Timestamp;
import org.tokenscript.attestation.UseAttestation;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.URLUtility;
import org.tokenscript.attestation.eip712.Eip712AttestationUsageEncoder.AttestationUsageData;
import org.tokenscript.eip712.Eip712Signer;
import org.tokenscript.eip712.Eip712Test;

public class TestAttestationUsageEip712 {
  private static final String DOMAIN = "https://www.hotelbogota.com";
  private static final String MAIL = "email@test.com";
  private static final AttestationType TYPE = AttestationType.EMAIL;
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("15816808484023");
  private static final long CHAIN_ID = 1;
  private static final Eip712AttestationUsageEncoder encoder = new Eip712AttestationUsageEncoder(CHAIN_ID);

  private static byte[] nonce;
  private static FullProofOfExponent pok;
  private static SignedIdentifierAttestation signedAttestation;
  private static AsymmetricCipherKeyPair attestorKeys;
  private static AsymmetricKeyParameter userSigningKey;
  private static AsymmetricKeyParameter sessionKey;
  private static String userAddress;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    // added sender keys to align keys with DEMO. keys order changed.
    AsymmetricCipherKeyPair senderKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    AsymmetricCipherKeyPair userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    attestorKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    userSigningKey = userKeys.getPrivate();
    userAddress = SignatureUtility.addressFromKey(userKeys.getPublic());
    nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    IdentifierAttestation att = HelperTest
        .makeUnsignedStandardAtt(userKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    signedAttestation = new SignedIdentifierAttestation(att, attestorKeys);
    X9ECParameters SECT283K1 = SECNamedCurves.getByName("sect283k1");
    sessionKey = SignatureUtility.constructECKeys(SECT283K1, rand).getPublic();
  }

  @BeforeEach
  public void init() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void writeTestMaterial() throws Exception {
    FileImportExport.storeKey(attestorKeys.getPublic(), "eip712-att-req-usage-key");
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL,
        usage, userSigningKey);
    FileImportExport.storeToken(request.getJsonEncoding(), "eip712-att-req-usage");

    // Validate loading
    AsymmetricKeyParameter eip712TicketKey = FileImportExport.loadPubKey("eip712-att-req-usage-key"
        + ".txt");
    String decodedToken = FileImportExport.loadToken("eip712-att-req-usage");
    Eip712AttestationUsage req = new Eip712AttestationUsage(DOMAIN, eip712TicketKey, decodedToken);
    assertTrue(req.checkTokenValidity());
    assertTrue(req.verify());
  }

  @Test
  void referenceJsonFormat() {
    String request = "{\"signatureInHex\":\"0x2396cde0c922693ad14a8496b4ad8418edd55c0d22b134e9823edbede910f3114ef885039d011662f4f7ce607b1985c0f97c32522cb78d8ad47aea4c09a398231b\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"}]},\\\"primaryType\\\":\\\"AttestationUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIIEnTCCAkwwggH5oAMCARICAQEwCQYHKoZIzj0EAjAOMQwwCgYDVQQDDANBTFgwLhgPMjAyMjAzMjQxMjE4MThaAgRiPGGKGA8yMDMyMDMyMTEyMTgxOFoCBHUIZIowCzEJMAcGA1UEAwwAMIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA_____________________________________v___C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5hIOtp3JqPEZV2k-_wOEQio_Re0SKaFVBmcR9CP-xDUuAIhAP____________________66rtzmr0igO7_SXozQNkFBAgEBA0IABNNj3-rhhwxBABhmJpTmPZzkcJ6mElV8GFTdL8aGGsseXxiO8jZNWjDMFSqKAPOHT8sVZV66_uNVTxKQgDgZ8_EwBwIBKgICBTmjVzBVMFMGCysGAQQBizpzeQEoAQH_BEEEBf4waGibxLr-xOtIPTqSyPUm7VhND0Wemc6TpRIpCgQVYa-Hh9BK_SkBIguxAbZb1l_SGiHV9mTj-uzDq4UDCTAJBgcqhkjOPQQCA0IAEDlbV7apQ916acvzZjx-loOTGfLAHrq_ZoLrCJTuWlgjOzsbBLgsK5UUXjqjWxOtOLLBOQhTNF7ewvRLqd8hPxsCAQEwgfwEQQQetkj_nYGbQHpsWNJ5eHI8TltFCsmJgzzs9v2HwxYM3gmt2VZXjp4go3k37qEfTU2rXXKDOCK7sM0lL_g54kG3BCAqodsH2iDEWdpI3WUN3xZhzoVHblgd-knV_-3xLIWRGQRBBArui58APwMxF83AK3AuCNBAnE500oxmxhdfs8GjA2kXIF-K6ji3fpzTtpqHDd2AMcrosNJ1BAR2tpR2Ip2FukEEUjBYNUY3QkZFNzUyQUMxQTQ1RjY3NDk3RDlEQ0REOUJCREE1MEE4Mzk1NcBxJpS6VWwViG_3TFMX3w_C5Rk1h9lTxNkbTSZP6dyrAAABf7vdAxAwggFHMIH4BgcqhkjOPQIBMIHsAgEBMCUGByqGSM49AQIwGgICARsGCSqGSM49AQIDAzAJAgEFAgEHAgEMMEwEJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBEkEBQMhP3jKRIg_GjuBYvGI5VPNJl8jwVZ6FodpE7DCrCRYSSg2AczaOA8cnjGNkPldB-VCb-h-RcDoGEaY5FliNk40EWF33SJZAiQB_______________________pri7QdXcmXf9_lEUeBh4WPGECAQQDSgAEAU0LBiRPJvqOUJ-vR0YpncGsvKo_b9CHvpRg00x5BNDEt6UKAZugFiCZLf7_nT12DRsph7PE9PvwTIbUQt8S7We1E-MCkMjH\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identifier\\\\\\\" is the identifier hidden in attestation contained in\\\\\\\"payload\\\\\\\".\\\",\\\"timestamp\\\":\\\"Thu Mar 24 2022 12:18:26 GMT+0000\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Sat Mar 23 10052 11:18:25 GMT+0000\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.hotelbogota.com\\\",\\\"version\\\":\\\"0.1\\\",\\\"chainId\\\":42}}\"}";
    Eip712AttestationUsage eiprequest = new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(),
            Timestamp.UNLIMITED, 42, request);
    assertTrue(eiprequest.verify());
    assertTrue(eiprequest.checkTokenValidity());
  }

  @Test
  void testSunshine() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    assertTrue(usage.verify());
    assertTrue(usage.checkValidity());
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  void otherTimeLimit() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    assertTrue(usage.verify());
    assertTrue(usage.checkValidity());
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, Timestamp.UNLIMITED, 42, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  void testDecoding() throws Exception {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    Eip712AttestationUsage newRequest = new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), request.getJsonEncoding());
    assertTrue(newRequest.verify());
    assertTrue(newRequest.checkTokenValidity());

    assertEquals(request.getIdentifier(), newRequest.getIdentifier());
    assertTrue(AttestationCrypto.verifyFullProof(newRequest.getPok()));
    assertArrayEquals(request.getPok().getDerEncoding(), newRequest.getPok().getDerEncoding());
    assertTrue(newRequest.getAttestation().verify());
    assertTrue(newRequest.getAttestation().checkValidity());
    assertArrayEquals(request.getAttestation().getDerEncoding(), newRequest.getAttestation().getDerEncoding());
    assertEquals(request.getJsonEncoding(), newRequest.getJsonEncoding());
    assertEquals(request.getType(), newRequest.getType());
    assertArrayEquals(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(sessionKey).getEncoded(),
        SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(newRequest.getSessionPublicKey()).getEncoded());
    assertEquals( ((ECKeyParameters) request.getUserPublicKey()).getParameters(),
        ((ECKeyParameters) newRequest.getUserPublicKey()).getParameters());
  }

  @Test
  void eipEncoding() throws Exception {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    Eip712Test.validateEncoding(encoder, request.getJsonEncoding());
  }

  @Test
  void eipSignableEncoding() throws Exception {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Timestamp now = new Timestamp();
    Timestamp expirationTime = new Timestamp(now.getTime() + 1000);
    AttestationUsageData data = new AttestationUsageData(
            encoder.getUsageValue(),
            MAIL, URLUtility.encodeData(usage.getDerEncoding()), now, expirationTime);
    Eip712Signer<AttestationUsageData> issuer = new Eip712Signer<>(userSigningKey, encoder);
    String json = issuer.buildSignedTokenFromJsonObject(data.getSignableVersion(), DOMAIN);
    Eip712Test.validateEncoding(encoder, json);
  }

  @Test
  void badAttesattion() {
    Mockito.when(mockedUseAttestation.getDerEncoding()).thenReturn(new byte[0]);
    Mockito.when(mockedUseAttestation.verify()).thenReturn(false);
    Exception e = assertThrows(IllegalArgumentException.class, () -> new Eip712AttestationUsage(DOMAIN, MAIL, mockedUseAttestation, userSigningKey));
    assertEquals("Could not verify object", e.getMessage());
  }

  @Test
  void expiredToken() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, -Timestamp.ALLOWED_ROUNDING * 2, CHAIN_ID,
            MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  void invalidNonceDomain() {
    byte[] wrongNonce = Nonce.makeNonce(userAddress, "http://www.notTheRightHotel.com", new Timestamp());
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, wrongPok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  void invalidNonceAddress() {
    byte[] wrongNonce = new byte[]{0x01, 0x02, 0x03};
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, wrongPok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  void invalidNonceBadIdentifier() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, "notTheRight@email.com", usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Mock
  UseAttestation mockedUseAttestation;

  @Test
  void invalidUseAttestation() {
    Mockito.when(mockedUseAttestation.verify()).thenReturn(true);
    Mockito.when(mockedUseAttestation.getDerEncoding()).thenReturn(new byte[]{0x00});
    Mockito.when(mockedUseAttestation.getAttestation()).thenReturn(signedAttestation);
    Mockito.when(mockedUseAttestation.getPok()).thenReturn(pok);
    Mockito.when(mockedUseAttestation.getType()).thenReturn(TYPE);
    Mockito.when(mockedUseAttestation.checkValidity()).thenReturn(false);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, mockedUseAttestation, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  void nonverifiableUseAttesation() {
    // First verification is done in the constructor of Eip712AttestationUsage
    Mockito.when(mockedUseAttestation.verify()).thenReturn(true).thenReturn(false);
    Mockito.when(mockedUseAttestation.getDerEncoding()).thenReturn(new byte[]{0x00});
    Mockito.when(mockedUseAttestation.getAttestation()).thenReturn(signedAttestation);
    Mockito.when(mockedUseAttestation.getPok()).thenReturn(pok);
    Mockito.when(mockedUseAttestation.getType()).thenReturn(TYPE);
    Mockito.when(mockedUseAttestation.checkValidity()).thenReturn(true);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, mockedUseAttestation, userSigningKey);
    assertFalse(request.verify());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  void invalidProofLinking() {
    // Wrong type
    UseAttestation usage = new UseAttestation(signedAttestation, AttestationType.PHONE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  void badAddressInNonce() {
    AsymmetricCipherKeyPair otherUserKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    IdentifierAttestation att = HelperTest
            .makeUnsignedStandardAtt(otherUserKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedIdentifierAttestation otherSingedAttestation = new SignedIdentifierAttestation(att, attestorKeys);
    UseAttestation usage = new UseAttestation(otherSingedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertFalse(request.checkTokenValidity());
  }

  @Test
  void invalidConstructor() {
    Mockito.when(mockedUseAttestation.verify()).thenReturn(true);
    Mockito.when(mockedUseAttestation.getDerEncoding()).thenReturn(null);
    // Wrong signing keys
    Exception e = assertThrows(IllegalArgumentException.class, () -> new Eip712AttestationUsage(DOMAIN, MAIL, mockedUseAttestation,
            userSigningKey));
    assertEquals("Could not encode asn1", e.getMessage());
  }

  @Test
  void invalidOtherConstructor() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    String json = request.getJsonEncoding();
    String wrongJson = json.replace(',', '.');
    Exception e = assertThrows(IllegalArgumentException.class, () -> new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), wrongJson));
    assertEquals("Could not decode asn1", e.getMessage());
  }


  @Test
  void wrongSignature() {
    String jsonInvalidSig = "{\"signatureInHex\":\"0xe46f9fb4a4df834b2b83cc75817919af9a69ee0350bd4bb1a421080d5974424800f66b55700e3be26103c2ee89fd646bcb0d721656d2e18e2de78881e7a611e61c\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"}]},\\\"primaryType\\\":\\\"AttestationUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIIEnTCCAkwwggH5oAMCARICAQEwCQYHKoZIzj0EAjAOMQwwCgYDVQQDDANBTFgwLhgPMjAyMjA1MjAxMzQyMjhaAgRih5rEGA8yMDMyMDUxNzEzNDI0M1oCBHVTndMwCzEJMAcGA1UEAwwAMIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA_____________________________________v___C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5hIOtp3JqPEZV2k-_wOEQio_Re0SKaFVBmcR9CP-xDUuAIhAP____________________66rtzmr0igO7_SXozQNkFBAgEBA0IABNNj3-rhhwxBABhmJpTmPZzkcJ6mElV8GFTdL8aGGsseXxiO8jZNWjDMFSqKAPOHT8sVZV66_uNVTxKQgDgZ8_EwBwIBKgICBTmjVzBVMFMGCysGAQQBizpzeQEoAQH_BEEEBf4waGibxLr-xOtIPTqSyPUm7VhND0Wemc6TpRIpCgQVYa-Hh9BK_SkBIguxAbZb1l_SGiHV9mTj-uzDq4UDCTAJBgcqhkjOPQQCA0IAwzeiNwHfnk9f9Npkh9_iWLl6DV8VIdqCc_Dud-yygJ0Qlt_rRzooGOfmi3uaeBwLO5hPOCkbRPVKJo989qd7hBsCAQEwgfwEQQQetkj_nYGbQHpsWNJ5eHI8TltFCsmJgzzs9v2HwxYM3gmt2VZXjp4go3k37qEfTU2rXXKDOCK7sM0lL_g54kG3BCAoyU3VhYrmjwVHG9q6GJc9HM88VSjvfKl5L2gGR8sXaARBBCuONwsSB9Elx41TAs_HPLwWHh3xXgxfrzgjy1qpzdiUBiv-iUljSzooGoQBeMBczcmtts1rujewpgQ4U9-i5V8EUjBYNUY3QkZFNzUyQUMxQTQ1RjY3NDk3RDlEQ0REOUJCREE1MEE4Mzk1NcBxJpS6VWwViG_3TFMX3w_C5Rk1h9lTxNkbTSZP6dyrAAABgOG0yDgwggFHMIH4BgcqhkjOPQIBMIHsAgEBMCUGByqGSM49AQIwGgICARsGCSqGSM49AQIDAzAJAgEFAgEHAgEMMEwEJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBEkEBQMhP3jKRIg_GjuBYvGI5VPNJl8jwVZ6FodpE7DCrCRYSSg2AczaOA8cnjGNkPldB-VCb-h-RcDoGEaY5FliNk40EWF33SJZAiQB_______________________pri7QdXcmXf9_lEUeBh4WPGECAQQDSgAEByc72m2s0_jBop-62ySxOmAR5gw32JVHF50_cmbjxnFYwHEsAUMY0LO578TX5xO7FMuir1CEu8V1tiq1TpyIOVz-M_xl84Hr\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identifier\\\\\\\" is the identifier hidden in attestation contained in\\\\\\\"payload\\\\\\\".\\\",\\\"timestamp\\\":\\\"Fri May 20 2022 13:42:44 GMT+0000\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Sat May 20 2023 13:42:44 GMT+0000\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.hotelbogota.com\\\",\\\"version\\\":\\\"0.1\\\",\\\"chainId\\\":0}}\"}";
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), Timestamp.UNLIMITED, 0, jsonInvalidSig);
    assertTrue(request.verify());
    // Should fail since the nonce is based on the real public key and not the wrong one recovered from the signature
    assertFalse(request.checkTokenValidity());
  }

  @Test
  void checkKeyRecovery() {
    // Request with modified signature but signed with "userSigningKey"
    String jsonInvalidSig = "{\"signatureInHex\":\"0xe46f9fb4a4df834b2b83cc75817919af9a69ee0350bd4bb1a421080d5974424800f66b55700e3be26103c2ee89fd646bcb0d721656d2e18e2de78881e7a611e61c\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"}]},\\\"primaryType\\\":\\\"AttestationUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIIEnTCCAkwwggH5oAMCARICAQEwCQYHKoZIzj0EAjAOMQwwCgYDVQQDDANBTFgwLhgPMjAyMjA1MjAxMzQyMjhaAgRih5rEGA8yMDMyMDUxNzEzNDI0M1oCBHVTndMwCzEJMAcGA1UEAwwAMIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA_____________________________________v___C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5hIOtp3JqPEZV2k-_wOEQio_Re0SKaFVBmcR9CP-xDUuAIhAP____________________66rtzmr0igO7_SXozQNkFBAgEBA0IABNNj3-rhhwxBABhmJpTmPZzkcJ6mElV8GFTdL8aGGsseXxiO8jZNWjDMFSqKAPOHT8sVZV66_uNVTxKQgDgZ8_EwBwIBKgICBTmjVzBVMFMGCysGAQQBizpzeQEoAQH_BEEEBf4waGibxLr-xOtIPTqSyPUm7VhND0Wemc6TpRIpCgQVYa-Hh9BK_SkBIguxAbZb1l_SGiHV9mTj-uzDq4UDCTAJBgcqhkjOPQQCA0IAwzeiNwHfnk9f9Npkh9_iWLl6DV8VIdqCc_Dud-yygJ0Qlt_rRzooGOfmi3uaeBwLO5hPOCkbRPVKJo989qd7hBsCAQEwgfwEQQQetkj_nYGbQHpsWNJ5eHI8TltFCsmJgzzs9v2HwxYM3gmt2VZXjp4go3k37qEfTU2rXXKDOCK7sM0lL_g54kG3BCAoyU3VhYrmjwVHG9q6GJc9HM88VSjvfKl5L2gGR8sXaARBBCuONwsSB9Elx41TAs_HPLwWHh3xXgxfrzgjy1qpzdiUBiv-iUljSzooGoQBeMBczcmtts1rujewpgQ4U9-i5V8EUjBYNUY3QkZFNzUyQUMxQTQ1RjY3NDk3RDlEQ0REOUJCREE1MEE4Mzk1NcBxJpS6VWwViG_3TFMX3w_C5Rk1h9lTxNkbTSZP6dyrAAABgOG0yDgwggFHMIH4BgcqhkjOPQIBMIHsAgEBMCUGByqGSM49AQIwGgICARsGCSqGSM49AQIDAzAJAgEFAgEHAgEMMEwEJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBEkEBQMhP3jKRIg_GjuBYvGI5VPNJl8jwVZ6FodpE7DCrCRYSSg2AczaOA8cnjGNkPldB-VCb-h-RcDoGEaY5FliNk40EWF33SJZAiQB_______________________pri7QdXcmXf9_lEUeBh4WPGECAQQDSgAEByc72m2s0_jBop-62ySxOmAR5gw32JVHF50_cmbjxnFYwHEsAUMY0LO578TX5xO7FMuir1CEu8V1tiq1TpyIOVz-M_xl84Hr\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identifier\\\\\\\" is the identifier hidden in attestation contained in\\\\\\\"payload\\\\\\\".\\\",\\\"timestamp\\\":\\\"Fri May 20 2022 13:42:44 GMT+0000\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Sat May 20 2023 13:42:44 GMT+0000\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.hotelbogota.com\\\",\\\"version\\\":\\\"0.1\\\",\\\"chainId\\\":0}}\"}";
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), Timestamp.UNLIMITED, 0, jsonInvalidSig);
    AsymmetricKeyParameter candidateKey = request.retrieveUserPublicKey(request.getJsonEncoding(), Eip712AttestationRequestWithUsageEncoder.AttestationRequestWUsageData.class);
    assertNotEquals(userAddress, SignatureUtility.addressFromKey(candidateKey));
  }

  @Test
  void validateWrongNonceKey() {
    // Notice the wrong address
    byte[] nonce = Nonce.makeNonce("0x1234567890123456789012345678901234567890", DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    UseAttestation attRequest = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, attRequest, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  void wrongDomain() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    assertTrue(usage.verify());
    assertTrue(usage.checkValidity());
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkTokenValidity());
    // Request with wrong chain
    Eip712AttestationUsage wrongRequest = new Eip712AttestationUsage("http://www.nope.com", attestorKeys.getPublic(), request.getJsonEncoding());
    assertTrue(wrongRequest.verify());
    assertFalse(wrongRequest.checkTokenValidity());
  }
}
