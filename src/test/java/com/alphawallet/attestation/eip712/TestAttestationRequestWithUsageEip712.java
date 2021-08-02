package com.alphawallet.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestationRequestWithUsage;
import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.eip712.Eip712AttestationRequestWithUsageEncoder.AttestationRequestWUsageData;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import org.tokenscript.eip712.Eip712Issuer;
import org.tokenscript.eip712.Eip712Test;

public class TestAttestationRequestWithUsageEip712 {
  private static final Logger logger = LogManager.getLogger(TestAttestationRequestWithUsageEip712.class);
  private static final String DOMAIN = "https://www.attestation.id";
  private static final String MAIL = "email@test.com";
  private static final AttestationType TYPE = AttestationType.EMAIL;
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("15816808484023");
  private static final Eip712AttestationRequestWithUsageEncoder encoder = new Eip712AttestationRequestWithUsageEncoder();

  private static byte[] nonce;
  private static FullProofOfExponent pok;
  private static AttestationRequestWithUsage requestWithUsage;
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
    attestorKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    AsymmetricCipherKeyPair userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    userSigningKey = userKeys.getPrivate();
    X9ECParameters SECT283K1 = SECNamedCurves.getByName("sect283k1");
    sessionKey = SignatureUtility.constructECKeys(SECT283K1, rand).getPublic();
    userAddress = SignatureUtility.addressFromKey(userKeys.getPublic());
    nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    requestWithUsage = new AttestationRequestWithUsage(TYPE, pok, sessionKey);
    assertTrue(requestWithUsage.verify());
  }

  @BeforeEach
  public void init() {
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void referenceJsonFormat() {
   String request = "{\"signatureInHex\":\"0x7115b0772ef6767a7177e4e74f4c846317e9d93508f6c802cf27efedbb8546d1532675cadd90a2de7297924eea98db32a6e5f5315bdcaa3b5190af9d6cb772741c\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationRequestWUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"}]},\\\"primaryType\\\":\\\"AttestationRequestWUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIICOQIBATCB_ARBBCt8Oc39N5KeRD-fKHXSoiH-gaNFccz_Hm2QZ9pacWIMFAemqwLlkr9_0GOio0IgnRDiX7zNgfj8yrMi-s37QcYEIBEfndhVif8Z5z5Dc8_aVo3IT_1oDwVOgYneM4XpuUxmBEEEKY-axBy7A1Y7UiIH5DFAu9VMS2YD57VCOtkO01qVtjYrnOC91D9OQziWNRjCL6NoV8oxzhhW6xrvVk_OdjpJEwRSMFg1RjdCRkU3NTJBQzFBNDVGNjc0OTdEOURDREQ5QkJEQTUwQTgzOTU1Sm1UC7EZ7FbQ1gD2qvRqimx8roUC_TlKlL_iMtn-uNsAAAF6uR0tWDCCATMwgewGByqGSM49AgEwgeACAQEwLAYHKoZIzj0BAQIhAP____8AAAABAAAAAAAAAAAAAAAA________________MEQEIP____8AAAABAAAAAAAAAAAAAAAA_______________8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw-J9JgSwRBBGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfUCIQD_____AAAAAP__________vOb6racXnoTzucrC_GMlUQIBAQNCAAQ6sGTRni1PlKwyOJfXVMU1MjA6gCViaG_7L30DDrE5xnFlhUTdc1P5Bh2KpEf6Rqyn6ACygcstbgjHNjmTBKUq\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identifier\\\\\\\" is the identifier hidden in attestation contained in\\\\\\\"payload\\\\\\\" and use this to authorize usage of local, temporary keys.\\\",\\\"timestamp\\\":\\\"Sun Jul 18 2021 10:15:35 GMT+0000\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Wed Aug 4 2021 10:56:03 GMT+0000\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.attestation.id\\\",\\\"version\\\":\\\"0.1\\\"}}\"}";
    Eip712AttestationRequestWithUsage eiprequest =
        new Eip712AttestationRequestWithUsage(DOMAIN, Timestamp.UNLIMITED, Timestamp.UNLIMITED, request);
    assertTrue(eiprequest.verify());
    assertTrue(eiprequest.checkValidity());
    assertTrue(eiprequest.checkTokenValidity());
    Eip712AttestationRequestWithUsage lessValidRequest =
        new Eip712AttestationRequestWithUsage(DOMAIN, 1000L*10L, Timestamp.UNLIMITED, request);
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
  public void testSunshine() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  public void otherTimeLimit() throws Exception {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN,  1000L*60L, Timestamp.UNLIMITED, MAIL, requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
    assertTrue(request.checkTokenValidity());
  }


  @Test
  public void testDecoding() throws Exception {
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
  public void eipEncoding() throws Exception {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        requestWithUsage, userSigningKey);
    Eip712Test.validateEncoding(encoder, request.getJsonEncoding());
  }

  @Test
  public void eipSignableEncoding() throws Exception {
    Timestamp now = new Timestamp();
    Timestamp expirationTime = new Timestamp(now.getTime() + 1000);
    AttestationRequestWUsageData data = new AttestationRequestWUsageData(
        encoder.getUsageValue(), MAIL, URLUtility.encodeData(requestWithUsage.getDerEncoding()), now, expirationTime);
    Eip712Issuer issuer = new Eip712Issuer<AttestationRequestWUsageData>(userSigningKey, encoder);
    String json = issuer.buildSignedTokenFromJsonObject(data.getSignableVersion(), DOMAIN);
    Eip712Test.validateEncoding(encoder, json);
  }

  @Test
  public void badSignature() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        requestWithUsage, userSigningKey);
    byte[] encoding = request.getJsonEncoding().getBytes(StandardCharsets.UTF_8);
    // Flip a bit in the signature part of the encoding
    encoding[40] ^= 0x01;
    assertThrows(IllegalArgumentException.class,
        () -> new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), new String(encoding)));
  }

  @Test
  public void expiredToken() throws Exception {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, Timestamp.DEFAULT_TIME_LIMIT_MS, -1,
        MAIL, requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  public void invalidTimestamp() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, -1,
        Timestamp.DEFAULT_TOKEN_TIME_LIMIT, MAIL, requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  public void invalidNonceDomain() {
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
  public void invalidNonce() {
    byte[] wrongNonce = new byte[] {0x01, 0x02, 0x03};
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
  public void nonVerifiableUseAttestation() {
    // First verification is done in the constructor of Eip712AttestationUsage
    Mockito.when(mockedAttReqUsage.verify()).thenReturn(true).thenReturn(false);
    Mockito.when(mockedAttReqUsage.getDerEncoding()).thenReturn(new byte[] {0x00});
    Mockito.when(mockedAttReqUsage.getPok()).thenReturn(pok);
    Mockito.when(mockedAttReqUsage.getType()).thenReturn(TYPE);
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        mockedAttReqUsage, userSigningKey);
    assertFalse(request.verify());
    assertTrue(request.checkValidity());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  public void invalidConstructor() {
    Mockito.when(mockedAttReqUsage.verify()).thenReturn(true);
    Mockito.when(mockedAttReqUsage.getDerEncoding()).thenReturn(null);
    // Wrong signing keys
    Exception e = assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        mockedAttReqUsage,
        userSigningKey));
    assertEquals("Could not encode object", e.getMessage());
  }

  @Test
  public void invalidOtherConstructor() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL,
        requestWithUsage,
        userSigningKey);
    String json = request.getJsonEncoding();
    String wrongJson = json.replace(',', '.');
    Exception e = assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequestWithUsage(DOMAIN, wrongJson));
    assertEquals("Could not decode object", e.getMessage());
  }

}
