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
import com.alphawallet.attestation.core.Nonce;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.eip712.Eip712AttestationRequestWithUsageEncoder.AttestationRequestWUsageData;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.time.Clock;
import java.util.Date;
import java.util.Locale;
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
import org.tokenscript.eip712.Eip712Validator;

public class TestAttestationRequestWithUsageEip712 {
  private static final String DOMAIN = "https://www.hotelbogota.com";
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
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    attestorKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    AsymmetricCipherKeyPair userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    userSigningKey = userKeys.getPrivate();
    X9ECParameters SECT283K1 = SECNamedCurves.getByName("sect283k1");
    sessionKey = SignatureUtility.constructECKeys(SECT283K1, rand).getPublic();
    userAddress = SignatureUtility.addressFromKey(userKeys.getPublic());
    nonce = Nonce.makeNonce(userAddress, DOMAIN, Clock.systemUTC().millis());
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
    String request = "{\"signatureInHex\":\"0xbe1d59c56070c19ced3e08d8abecb2375b1815979e009fe8f396afbecd89f6cb08baab073dd3584b3c5146c05ad64bf78b129fc3225fe0782504b4e2558251b51b\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationRequestWUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"}]},\\\"primaryType\\\":\\\"AttestationRequestWUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIICTQIBATCB_ARBBB62SP-dgZtAemxY0nl4cjxOW0UKyYmDPOz2_YfDFgzeCa3ZVleOniCjeTfuoR9NTatdcoM4IruwzSUv-DniQbcEIC631-FiKdeSfj4SpEU3F5ueNGhiXGjxABRqrkOJ1mEVBEEEDFVwBw77_sz-3PcHsmrwCbfzlcYJpvrh1dcYJCcxAAQlgxlEE72jadyvtgoUs-ttKmV-pQN0FXiBiBgU0q9vswRSMHg1RjdCRkU3NTJBQzFBNDVGNjc0OTdEOURDREQ5QkJEQTUwQTgzOTU1wHEmlLpVbBWIb_dMUxffD8LlGTWH2VPE2RtNJk_p3KsAAAF4adCYyjCCAUcwgfgGByqGSM49AgEwgewCAQEwJQYHKoZIzj0BAjAaAgIBGwYJKoZIzj0BAgMDMAkCAQUCAQcCAQwwTAQkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEESQQFAyE_eMpEiD8aO4Fi8YjlU80mXyPBVnoWh2kTsMKsJFhJKDYBzNo4DxyeMY2Q-V0H5UJv6H5FwOgYRpjkWWI2TjQRYXfdIlkCJAH______________________-muLtB1dyZd_3-URR4GHhY8YQIBBANKAAQFK7J9i33xUcv3NBo2Xh82NNDkiqCBaefEwx4sRgxdgUaXmNUHJ8zGwAtvOMuXXHqoJpsCyU_aPLbGNP7o0kTjE75DVoiAbHQ=\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identity\\\\\\\" is the identity hidden in attestation contained in\\\\\\\"payload\\\\\\\" and use this to authorize usage of local, temporary keys.\\\",\\\"timestamp\\\":\\\"Thu Mar 25 2021 15:36:22 GMT+0100\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Thu Apr 1 2021 16:36:22 GMT+0200\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.hotelbogota.com\\\",\\\"version\\\":\\\"0.1\\\"}}\"}";
    Eip712AttestationRequestWithUsage eiprequest =
        new Eip712AttestationRequestWithUsage(DOMAIN, 0, 1000*60*60*24*365*10, request);
    assertTrue(eiprequest.verify());
    assertTrue(eiprequest.checkValidity());
  }

  @Test
  public void testSunshine() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
  }

  @Test
  public void testDecoding() throws Exception {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, requestWithUsage, userSigningKey);
    Eip712AttestationRequestWithUsage newRequest = new Eip712AttestationRequestWithUsage(DOMAIN, request.getJsonEncoding());
    assertTrue(newRequest.verify());
    assertTrue(newRequest.checkValidity());

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
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, requestWithUsage, userSigningKey);
    Eip712Test.validateEncoding(encoder, request.getJsonEncoding());
  }

  @Test
  public void eipSignableEncoding() throws Exception {
    long now = Clock.systemUTC().millis();
    long expirationTime = now + 1000;
    AttestationRequestWUsageData data = new AttestationRequestWUsageData(
        encoder.getUsageValue(), MAIL, URLUtility.encodeData(requestWithUsage.getDerEncoding()), now, expirationTime);
    Eip712Issuer issuer = new Eip712Issuer<AttestationRequestWUsageData>(userSigningKey, encoder);
    String json = issuer.buildSignedTokenFromJsonObject(data.getSignableVersion(), DOMAIN);
    Eip712Test.validateEncoding(encoder, json);
  }

  @Test
  public void badSignature() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, requestWithUsage, userSigningKey);
    byte[] encoding = request.getJsonEncoding().getBytes(StandardCharsets.UTF_8);
    // Flip a bit in the signature part of the encoding
    encoding[40] ^= 0x01;
    assertThrows(IllegalArgumentException.class,
        () -> new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), new String(encoding)));
  }

  @Test
  public void expiredToken() throws Exception {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, Eip712AttestationRequestWithUsage.DEFAULT_TIME_LIMIT_MS, -1,  MAIL, userAddress, requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }

  @Test
  public void invalidTimestamp() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, Eip712AttestationRequestWithUsage.DEFAULT_TIME_LIMIT_MS, -1001, MAIL, userAddress, requestWithUsage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }

  @Test
  public void timestampInFuture() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, requestWithUsage, userSigningKey);
    long futureTime = Clock.systemUTC().millis() + Eip712Validator.DEFAULT_TIME_LIMIT_MS + 1000;
    long expirationTime = futureTime + Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT;
    String futureTimeString = encoder.TIMESTAMP_FORMAT.format(new Date(futureTime));
    String expirationTimeString = encoder.TIMESTAMP_FORMAT.format(new Date(expirationTime));
    assertFalse(request.validateTime(futureTimeString, expirationTimeString));
  }

  @Test
  public void timestampExpired() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, requestWithUsage, userSigningKey);
    long timestamp = Clock.systemUTC().millis() - Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT - Eip712Validator.DEFAULT_TIME_LIMIT_MS - 1000;
    long expirationTime = timestamp + Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT;
    String timestampString = encoder.TIMESTAMP_FORMAT.format(new Date(timestamp));
    String expirationTimeString = encoder.TIMESTAMP_FORMAT.format(new Date(expirationTime));
    assertFalse(request.validateTime(timestampString, expirationTimeString));
  }

  @Test
  public void timestampFromPastOk() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, requestWithUsage, userSigningKey);
    long timestamp = Clock.systemUTC().millis() - Eip712Validator.DEFAULT_TIME_LIMIT_MS - 1000;
    long expirationTime = timestamp + Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT;
    String timestampString = encoder.TIMESTAMP_FORMAT.format(new Date(timestamp));
    String expirationTimeString = encoder.TIMESTAMP_FORMAT.format(new Date(expirationTime));
    assertTrue(request.validateTime(timestampString, expirationTimeString));
  }

  @Test
  public void validForTooLong() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, requestWithUsage, userSigningKey);
    long timestamp = Clock.systemUTC().millis();
    long expirationTime = timestamp + Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT + Eip712Validator.DEFAULT_TIME_LIMIT_MS + 1;
    String timestampString = encoder.TIMESTAMP_FORMAT.format(new Date(timestamp));
    String expirationTimeString = encoder.TIMESTAMP_FORMAT.format(new Date(expirationTime));
    assertFalse(request.validateTime(timestampString, expirationTimeString));
  }

  @Test
  public void invalidTimeFormat() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, requestWithUsage, userSigningKey);
    long timestamp = Clock.systemUTC().millis();
    long expirationTime = timestamp + Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT;
    String timestampString = encoder.TIMESTAMP_FORMAT.format(new Date(timestamp));
    SimpleDateFormat otherFormat = new SimpleDateFormat("EEE MMM d yyyy HH:mm:ss", Locale.US);
    String expirationTimeString = otherFormat.format(new Date(expirationTime));
    assertThrows(RuntimeException.class, ()-> request.validateTime(timestampString, expirationTimeString));
  }

  @Test
  public void invalidNonceDomain() {
    byte[] wrongNonce = Nonce.makeNonce(userAddress, "http://www.notTheRightHotel.com", Clock.systemUTC().millis());
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    AttestationRequestWithUsage usage = new AttestationRequestWithUsage(TYPE, wrongPok, sessionKey);
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }

  @Test
  public void invalidNonce() {
    byte[] wrongNonce = new byte[] {0x01, 0x02, 0x03};
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    AttestationRequestWithUsage usage = new AttestationRequestWithUsage(TYPE, wrongPok, sessionKey);
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
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
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, mockedAttReqUsage, userSigningKey);
    assertFalse(request.verify());
    assertTrue(request.checkValidity());
  }

  @Test
  public void invalidConstructor() {
    Mockito.when(mockedAttReqUsage.verify()).thenReturn(true);
    Mockito.when(mockedAttReqUsage.getDerEncoding()).thenReturn(null);
    // Wrong signing keys
    Exception e = assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, mockedAttReqUsage,
        userSigningKey));
    assertEquals("Could not encode object", e.getMessage());
  }

  @Test
  public void invalidOtherConstructor() {
    Eip712AttestationRequestWithUsage request = new Eip712AttestationRequestWithUsage(DOMAIN, MAIL, userAddress, requestWithUsage,
        userSigningKey);
    String json = request.getJsonEncoding();
    String wrongJson = json.replace(',', '.');
    Exception e = assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequestWithUsage(DOMAIN, wrongJson));
    assertEquals("Could not decode object", e.getMessage());
  }

}
