package org.tokenscript.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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
import org.tokenscript.attestation.AttestationRequestWithUsage;
import org.tokenscript.attestation.FileImportExport;
import org.tokenscript.attestation.FullProofOfExponent;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.Timestamp;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.URLUtility;
import org.tokenscript.attestation.eip712.Eip712AttestationRequestWithUsageEncoder.AttestationRequestWUsageData;
import org.tokenscript.eip712.Eip712Signer;
import org.tokenscript.eip712.Eip712Test;

public class TestAttestationRequestWithUsageEip712 {
  private static final String DOMAIN = "https://www.attestation.id";
  private static final String MAIL = "email@test.com";
  private static final AttestationType TYPE = AttestationType.EMAIL;
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("15816808484023");
  private static final Eip712AttestationRequestWithUsageEncoder encoder = new Eip712AttestationRequestWithUsageEncoder();

  private static FullProofOfExponent pok;
  private static AttestationRequestWithUsage requestWithUsage;
  private static AsymmetricCipherKeyPair attestorKeys;
  private static AsymmetricKeyParameter userSigningKey;
  private static AsymmetricKeyParameter sessionKey;
  private static String userAddress;
  private static AttestationCrypto crypto;

  @BeforeAll
  public static void setupKeys() throws Exception {
    SecureRandom rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    attestorKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    AsymmetricCipherKeyPair userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    userSigningKey = userKeys.getPrivate();
    X9ECParameters SECT283K1 = SECNamedCurves.getByName("sect283k1");
    sessionKey = SignatureUtility.constructECKeys(SECT283K1, rand).getPublic();
    userAddress = SignatureUtility.addressFromKey(userKeys.getPublic());
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    requestWithUsage = new AttestationRequestWithUsage(TYPE, pok, sessionKey);
    assertTrue(requestWithUsage.verify());
  }

  @BeforeEach
  public void init() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void writeTestMaterial() throws Exception {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        requestWithUsage, userSigningKey);
    FileImportExport.storeToken(request.getJsonEncoding(), "eip712-att-req-usage.txt");

    // Validate loading
    String decodedToken = FileImportExport.loadToken("eip712-att-req-usage.txt");
    Eip712AttestationRequestWithUsage req = new Eip712AttestationRequestWithUsage(DOMAIN,
        decodedToken);
    assertTrue(req.checkValidity());
    assertTrue(req.checkTokenValidity());
    assertTrue(req.verify());
  }

  @Test
  void referenceJsonFormat() {
    String request = "{\"signatureInHex\":\"0x81dcaa2cacd85a2cb731660778cfef76b0261423476d03b215638351cc14882b5dc29ef45402c61872cf63b54c30788041e7624c440b002780d569fc4fd1dd8e1b\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationRequestWUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"}]},\\\"primaryType\\\":\\\"AttestationRequestWUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIICTQIBATCB_ARBBB62SP-dgZtAemxY0nl4cjxOW0UKyYmDPOz2_YfDFgzeCa3ZVleOniCjeTfuoR9NTatdcoM4IruwzSUv-DniQbcEICIO6_fhc4D0RJEKC1yB3LGvEoXAatK60lC-ipFW-Y26BEEEDFVwBw77_sz-3PcHsmrwCbfzlcYJpvrh1dcYJCcxAAQlgxlEE72jadyvtgoUs-ttKmV-pQN0FXiBiBgU0q9vswRSMFg1RjdCRkU3NTJBQzFBNDVGNjc0OTdEOURDREQ5QkJEQTUwQTgzOTU1Sm1UC7EZ7FbQ1gD2qvRqimx8roUC_TlKlL_iMtn-uNsAAAF7FWOBwDCCAUcwgfgGByqGSM49AgEwgewCAQEwJQYHKoZIzj0BAjAaAgIBGwYJKoZIzj0BAgMDMAkCAQUCAQcCAQwwTAQkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEESQQFAyE_eMpEiD8aO4Fi8YjlU80mXyPBVnoWh2kTsMKsJFhJKDYBzNo4DxyeMY2Q-V0H5UJv6H5FwOgYRpjkWWI2TjQRYXfdIlkCJAH______________________-muLtB1dyZd_3-URR4GHhY8YQIBBANKAAQFK7J9i33xUcv3NBo2Xh82NNDkiqCBaefEwx4sRgxdgUaXmNUHJ8zGwAtvOMuXXHqoJpsCyU_aPLbGNP7o0kTjE75DVoiAbHQ=\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identifier\\\\\\\" is the identifier hidden in attestation contained in\\\\\\\"payload\\\\\\\" and use this to authorize usage of local, temporary keys.\\\",\\\"timestamp\\\":\\\"Thu Aug 5 2021 08:17:29 GMT+0000\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Sat Aug 5 10051 07:17:28 GMT+0000\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.attestation.id\\\",\\\"version\\\":\\\"0.1\\\"}}\"}";
    Eip712AttestationRequestWithUsage eiprequest =
            new Eip712AttestationRequestWithUsage(DOMAIN, Timestamp.UNLIMITED, Timestamp.UNLIMITED, request);
    assertTrue(eiprequest.verify());
    assertTrue(eiprequest.checkValidity());
    assertTrue(eiprequest.checkTokenValidity());
    Eip712AttestationRequestWithUsage lessValidRequest =
            new Eip712AttestationRequestWithUsage(DOMAIN, 1000L * 10L, Timestamp.UNLIMITED, request);
    assertTrue(lessValidRequest.verify());
    assertFalse(lessValidRequest.checkValidity());
    assertTrue(lessValidRequest.checkTokenValidity());
    Eip712AttestationRequestWithUsage leastValidRequest =
        new Eip712AttestationRequestWithUsage(DOMAIN, 1000L*10L, 1000L*60L*20L, request);
    assertTrue(leastValidRequest.verify());
    assertFalse(leastValidRequest.checkValidity());
    // Note that the server trumps the limit on validity even if the client tries to construct a toke to last for 10 years
    assertFalse(leastValidRequest.checkTokenValidity());
  }

  @Test
  void testSunshine() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
            requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  void otherTimeLimit() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, 1000L * 60L, Timestamp.UNLIMITED, MAIL, requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
    assertTrue(request.checkTokenValidity());
  }


  @Test
  void testDecoding() throws Exception {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
            requestWithUsage, userSigningKey);
    Eip712AttestationRequestWithUsage newRequest = new Eip712AttestationRequestWithUsage(DOMAIN, request.getJsonEncoding());
    assertTrue(newRequest.verify());
    assertTrue(newRequest.checkValidity());
    assertTrue(newRequest.checkTokenValidity());

    assertEquals(request.getIdentifier(), newRequest.getIdentifier());
    assertEquals(request.getType(), newRequest.getType());
    assertTrue(AttestationCrypto.verifyFullProof(newRequest.getPok()));
    assertArrayEquals(request.getPok().getDerEncoding(), newRequest.getPok().getDerEncoding());
    assertEquals(request.getJsonEncoding(), newRequest.getJsonEncoding());
    assertEquals(request.getType(), newRequest.getType());
    assertArrayEquals(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(sessionKey).getEncoded(),
        SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(newRequest.getSessionPublicKey()).getEncoded());
    assertEquals( ((ECKeyParameters) request.getUserPublicKey()).getParameters(),
        ((ECKeyParameters) newRequest.getUserPublicKey()).getParameters());
  }

  @Test
  void eipEncoding() throws Exception {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
            requestWithUsage, userSigningKey);
    Eip712Test.validateEncoding(encoder, request.getJsonEncoding());
  }

  @Test
  void eipSignableEncoding() throws Exception {
    Timestamp now = new Timestamp();
    Timestamp expirationTime = new Timestamp(now.getTime() + 1000);
    AttestationRequestWUsageData data = new AttestationRequestWUsageData(
            encoder.getUsageValue(), MAIL, URLUtility.encodeData(requestWithUsage.getDerEncoding()), now, expirationTime);
    Eip712Signer<AttestationRequestWUsageData> issuer = new Eip712Signer<>(userSigningKey, encoder);
    String json = issuer.buildSignedTokenFromJsonObject(data.getSignableVersion(), DOMAIN);
    Eip712Test.validateEncoding(encoder, json);
  }

  @Test
  void badSignature() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
            requestWithUsage, userSigningKey);
    byte[] encoding = request.getJsonEncoding().getBytes(StandardCharsets.UTF_8);
    // Flip a bit in the signature part of the encoding
    encoding[40] ^= 0x01;
    assertThrows(IllegalArgumentException.class,
            () -> new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), new String(encoding)));
  }

  @Test
  void expiredToken() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, Timestamp.DEFAULT_TIME_LIMIT_MS, -Timestamp.ALLOWED_ROUNDING * 2,
            MAIL, requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  void invalidTimestamp() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, -Timestamp.ALLOWED_ROUNDING * 2,
            Timestamp.DEFAULT_TOKEN_TIME_LIMIT, MAIL, requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  void invalidNonceDomain() {
    byte[] wrongNonce = Nonce.makeNonce(userAddress, "http://www.notCorrect.com", new Timestamp());
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    AttestationRequestWithUsage usage = new AttestationRequestWithUsage(TYPE, wrongPok, sessionKey);
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
            usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  void invalidNonce() {
    byte[] wrongNonce = new byte[]{0x01, 0x02, 0x03};
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    AttestationRequestWithUsage usage = new AttestationRequestWithUsage(TYPE, wrongPok, sessionKey);
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
            usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
    assertFalse(request.checkTokenValidity());
  }

  @Mock
  AttestationRequestWithUsage mockedAttReqUsage;

  @Test
  void nonVerifiableUseAttestation() {
    // First verification is done in the constructor of Eip712AttestationUsage
    Mockito.when(mockedAttReqUsage.verify()).thenReturn(true).thenReturn(false);
    Mockito.when(mockedAttReqUsage.getDerEncoding()).thenReturn(new byte[]{0x00});
    Mockito.when(mockedAttReqUsage.getPok()).thenReturn(pok);
    Mockito.when(mockedAttReqUsage.getType()).thenReturn(TYPE);
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
            mockedAttReqUsage, userSigningKey);
    assertFalse(request.verify());
    assertTrue(request.checkValidity());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  void invalidConstructor() {
    Mockito.when(mockedAttReqUsage.verify()).thenReturn(true);
    Mockito.when(mockedAttReqUsage.getDerEncoding()).thenReturn(null);
    // Wrong signing keys
    Exception e = assertThrows(IllegalArgumentException.class, () -> new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
            mockedAttReqUsage,
            userSigningKey));
    assertEquals("Could not encode object", e.getMessage());
  }

  @Test
  void invalidOtherConstructor() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
            requestWithUsage,
            userSigningKey);
    String json = request.getJsonEncoding();
    String wrongJson = json.replace(',', '.');
    Exception e = assertThrows(IllegalArgumentException.class, () -> new Eip712AttestationRequestWithUsage(DOMAIN, wrongJson));
    assertEquals("Could not decode object", e.getMessage());
  }

  @Test
  void wrongSignature() {
    String jsonInvalidSig = "{\"signatureInHex\":\"0x5492e356581bf3a249d55245f25f52f25088434660aad9c37b6e86a7224a86877e6f472786c0dbb6f24268b0ea4891288b42be18e571a04ec2599f48714b28641c\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationRequestWUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"}]},\\\"primaryType\\\":\\\"AttestationRequestWUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIICTQIBATCB_ARBBB62SP-dgZtAemxY0nl4cjxOW0UKyYmDPOz2_YfDFgzeCa3ZVleOniCjeTfuoR9NTatdcoM4IruwzSUv-DniQbcEICBJ1TB0lMnjO3E4mRpuqh1hdjjYGc4RhOgHtA9PsD4iBEEEA2ka_nOn_7cfWROcSuXtb_BBX8bc7N8yi47FwS1_63oLadplUtvj7U0wrPVNmlzCZ98EqoEKXNZLGOmMpspqaARSMFg1RjdCRkU3NTJBQzFBNDVGNjc0OTdEOURDREQ5QkJEQTUwQTgzOTU1Sm1UC7EZ7FbQ1gD2qvRqimx8roUC_TlKlL_iMtn-uNsAAAGA4a6SYDCCAUcwgfgGByqGSM49AgEwgewCAQEwJQYHKoZIzj0BAjAaAgIBGwYJKoZIzj0BAgMDMAkCAQUCAQcCAQwwTAQkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEESQQFAyE_eMpEiD8aO4Fi8YjlU80mXyPBVnoWh2kTsMKsJFhJKDYBzNo4DxyeMY2Q-V0H5UJv6H5FwOgYRpjkWWI2TjQRYXfdIlkCJAH______________________-muLtB1dyZd_3-URR4GHhY8YQIBBANKAAQFK7J9i33xUcv3NBo2Xh82NNDkiqCBaefEwx4sRgxdgUaXmNUHJ8zGwAtvOMuXXHqoJpsCyU_aPLbGNP7o0kTjE75DVoiAbHQ=\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identifier\\\\\\\" is the identifier hidden in attestation contained in\\\\\\\"payload\\\\\\\" and use this to authorize usage of local, temporary keys.\\\",\\\"timestamp\\\":\\\"Fri May 20 2022 13:35:56 GMT+0000\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Sat May 20 2023 13:35:56 GMT+0000\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.attestation.id\\\",\\\"version\\\":\\\"0.1\\\"}}\"}";
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, Timestamp.UNLIMITED, Timestamp.UNLIMITED, jsonInvalidSig);
    assertTrue(request.verify());
    // Should fail since the nonce is based on the real public key and not the wrong one recovered from the signature
    assertFalse(request.checkValidity());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  void checkKeyRecovery() {
    // Request with modified signature but signed with "userSigningKey"
    String jsonInvalidSig = "{\"signatureInHex\":\"0x5492e356581bf3a249d55245f25f52f25088434660aad9c37b6e86a7224a86877e6f472786c0dbb6f24268b0ea4891288b42be18e571a04ec2599f48714b28641c\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationRequestWUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"}]},\\\"primaryType\\\":\\\"AttestationRequestWUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIICTQIBATCB_ARBBB62SP-dgZtAemxY0nl4cjxOW0UKyYmDPOz2_YfDFgzeCa3ZVleOniCjeTfuoR9NTatdcoM4IruwzSUv-DniQbcEICBJ1TB0lMnjO3E4mRpuqh1hdjjYGc4RhOgHtA9PsD4iBEEEA2ka_nOn_7cfWROcSuXtb_BBX8bc7N8yi47FwS1_63oLadplUtvj7U0wrPVNmlzCZ98EqoEKXNZLGOmMpspqaARSMFg1RjdCRkU3NTJBQzFBNDVGNjc0OTdEOURDREQ5QkJEQTUwQTgzOTU1Sm1UC7EZ7FbQ1gD2qvRqimx8roUC_TlKlL_iMtn-uNsAAAGA4a6SYDCCAUcwgfgGByqGSM49AgEwgewCAQEwJQYHKoZIzj0BAjAaAgIBGwYJKoZIzj0BAgMDMAkCAQUCAQcCAQwwTAQkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEESQQFAyE_eMpEiD8aO4Fi8YjlU80mXyPBVnoWh2kTsMKsJFhJKDYBzNo4DxyeMY2Q-V0H5UJv6H5FwOgYRpjkWWI2TjQRYXfdIlkCJAH______________________-muLtB1dyZd_3-URR4GHhY8YQIBBANKAAQFK7J9i33xUcv3NBo2Xh82NNDkiqCBaefEwx4sRgxdgUaXmNUHJ8zGwAtvOMuXXHqoJpsCyU_aPLbGNP7o0kTjE75DVoiAbHQ=\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identifier\\\\\\\" is the identifier hidden in attestation contained in\\\\\\\"payload\\\\\\\" and use this to authorize usage of local, temporary keys.\\\",\\\"timestamp\\\":\\\"Fri May 20 2022 13:35:56 GMT+0000\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Sat May 20 2023 13:35:56 GMT+0000\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.attestation.id\\\",\\\"version\\\":\\\"0.1\\\"}}\"}";
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, Timestamp.UNLIMITED, Timestamp.UNLIMITED, jsonInvalidSig);
    AsymmetricKeyParameter candidateKey = request.retrieveUserPublicKey(request.getJsonEncoding(), Eip712AttestationRequestWithUsageEncoder.AttestationRequestWUsageData.class);
    assertNotEquals(userAddress, SignatureUtility.addressFromKey(candidateKey));
  }

  @Test
  void validateWrongNonceKey() {
    // Notice the wrong address
    byte[] nonce = Nonce.makeNonce("0x1234567890123456789012345678901234567890", DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequestWithUsage attRequest = new AttestationRequestWithUsage(TYPE, pok, sessionKey);
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, Timestamp.UNLIMITED, Timestamp.UNLIMITED, MAIL, attRequest, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  void wrongDomain() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
            requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
    assertTrue(request.checkTokenValidity());
    // Request with wrong chain
    Eip712AttestationRequestWithUsage wrongRequest = new Eip712AttestationRequestWithUsage("http://www.nope.com", request.getJsonEncoding());
    assertTrue(wrongRequest.verify());
    assertFalse(wrongRequest.checkTokenValidity());
    assertFalse(wrongRequest.checkTokenValidity());
  }

}
