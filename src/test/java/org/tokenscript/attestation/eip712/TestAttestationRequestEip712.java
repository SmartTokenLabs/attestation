package org.tokenscript.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.tokenscript.attestation.AttestationRequest;
import org.tokenscript.attestation.FullProofOfExponent;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.Timestamp;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.URLUtility;
import org.tokenscript.attestation.eip712.Eip712AttestationRequestEncoder.AttestationRequestInternalData;
import org.tokenscript.eip712.Eip712Signer;
import org.tokenscript.eip712.Eip712Test;

public class TestAttestationRequestEip712 {
  private static final String DOMAIN = "http://www.hotelbogota.com";
  private static final String MAIL = "test@test.ts";
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");
  private static final AttestationType TYPE = AttestationType.EMAIL;
  private static final Eip712AttestationRequestEncoder encoder = new Eip712AttestationRequestEncoder(Eip712AttestationRequestEncoder.LISCON_USAGE_VALUE);

  private static AsymmetricKeyParameter userSigningKey;
  private static String userAddress;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    AsymmetricCipherKeyPair keys = SignatureUtility.constructECKeysWithSmallestY(rand);
    userSigningKey = keys.getPrivate();
    userAddress = SignatureUtility.addressFromKey(keys.getPublic());
  }

  @BeforeEach
  public void init() {
    MockitoAnnotations.initMocks(this);
  }

//  @Test
  public void validateJSToken() {
    // TODO update according to JS impl
    String request = "{\"signatureInHex\":\"0x6e2a95d19eb26e8a01b11d4ea694387a97f64030c880e0fd96b8378b913b4ec1632335d42781185cbd1044e6706eec1d08dafb063f86a47bf19b10faa85e07781c\",\"jsonSigned\":\"{\\\"domain\\\":{\\\"chainId\\\":3,\\\"name\\\":\\\"http://wwww.attestation.id\\\",\\\"version\\\":\\\"0.1\\\"},\\\"message\\\":{\\\"payload\\\":\\\"MIIBLQIBADCCASYEQQQjSSuHoeDrfflLEOw95Vc0kZHB6cz3pxpVsT6wgYXQaB9UHrziOybmB9Og6cD86Du1nP333I3k5vUogUa_9n5NBCADa4wSP3noAIpweaXuCgNJQGWIikjZiisEjFKg7SS_UQRBBAze02glDx9vj1SU6EDo3oNYR-qRam7m_tzhPffMchQgLTEM6Cf1hyytuly5ZfbhTyLKb90cTqw1QIoDIqn8W6AEfAAAAXhA_G5sdH-jiuhdX2vhv-GKUEDz1PufxLdKSXLUQOe9y48bbCgvIdwS3UO9FbhmQzMgQauXAQNX16mVOdMvZKl24jVJjabMI6iY8lztbg-HkIsPKqDcH4B8xdJGAYb3IzySfn2y3McDwOUAtlPKgic7e_rYBF2FpHA=\\\",\\\"description\\\":\\\"Linking Ethereum address to phone or email\\\",\\\"timestamp\\\":\\\"Wed Mar 17 2021 18:19:49 GMT+0200\\\",\\\"identifier\\\":\\\"test@test.com\\\",\\\"address\\\":\\\"0x2f21dc12dd43bd15b86643332041ab97010357d7\\\"},\\\"primaryType\\\":\\\"AttestationRequest\\\",\\\"types\\\":{\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"}],\\\"AttestationRequest\\\":[{\\\"name\\\":\\\"address\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"}]}}\"}";
    Eip712AttestationRequest eiprequest = new Eip712AttestationRequest("http://wwww.attestation.id",
        request);
    assertTrue(eiprequest.verify());
    assertTrue(eiprequest.checkValidity());
  }

  @Test
  public void eipBugFix() {
    String refRequest = "{\"signatureInHex\":\"0x68a63044ea9b2d8e64070507757fb4e830809ef485c36b6f0357b02902886b233e7c112758029d8f0bde30ee25b641b2371c4b6a31db554c8e35ec41176a23141c\",\"jsonSigned\":\"{\\\"types\\\":{\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"}],\\\"AttestationRequest\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"}]},\\\"primaryType\\\":\\\"AttestationRequest\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIIBAgIBATCB_ARBBBmSwTCP4VSOr07WYbuIZjR6oUIigLCB-o_ygrN2b2xxHKXEocXBQM3NLqQ5OkRuj0ogmOpKgwn7LhWYWkqNzvMEIC-Qz1C5I6i_3GDFC7F_WJdMtOe8X1Aspvy3QQe09Qe-BEEECsnXLNQdO2PgaHzQWGWg4KAQ4IvSkn1hPJotLPXMhPIuZeSry7aaOEQt64wyXUolp8an18193r5MKhfZ-E3AjQRSMFg3QTE4MUNCNzI1MDc3NkUxNjc4M0Y5RDNDOTE2NkRFMEY5NUFCMjgzr4crx6TxqXpXW2o9byWM8Ya4h7ATlfLav-aSz8hWQ8YAAAF_t5wJuA==\\\",\\\"description\\\":\\\"Creating email attestation\\\",\\\"timestamp\\\":\\\"Wed Mar 23 2022 16:28:51 GMT+0000\\\",\\\"identifier\\\":\\\"test@test.ts\\\"},\\\"domain\\\":{\\\"name\\\":\\\"http://www.hotelbogota.com\\\",\\\"version\\\":\\\"0.1\\\"}}\"}";
    String request = "{\"signatureInHex\":\"0x9fe797bff20a1b5904f8589c7af06363b56bb97c4d3aa0f802a8b669645f3efe69ea0fcf3b910b9277dfafc382667552488b4adc8a8eacdbf34835b24ef9541500\",\"jsonSigned\":\"{\\\"types\\\":{\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"}],\\\"AttestationRequest\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"}]},\\\"primaryType\\\":\\\"AttestationRequest\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIIBAgIBATCB_ARBBCMZ7_4K5jupelJXNctmyd3VvuV9fBMnATo0iEOfgaynL6StRLSmD_qvn_h6l7gyRj6vdg2LF9XCFnXfBqQ2rnEEIA8YIDJ4tN8RK8k0MdE1MKigxk2vrHX9OdnccFQ588zQBEEEDfCh9NDuU-TLojJa-rzBPdNXnkyT5PuZeSYXYNh-h9IV8i8pNS7KzKDuGL6lPHoREq7ZZFo07tvDdZdh-qvl7ARSMFgzRkYxQUVENUU5RkI1QTc1QUEzNEYzMzE2OTQzOEMxM0IzQzE5Qjc2qZU50y9kqXbiNUmNpswjqJjyXO1uD4eQiw8qoNwfgHwAAAF_pyFZfA\\\",\\\"description\\\":\\\"Creating email attestation\\\",\\\"timestamp\\\":\\\"Sun Mar 20 2022 13:40:55 GMT+0200\\\",\\\"identifier\\\":\\\"mah@mah.com\\\"},\\\"domain\\\":{\\\"name\\\":\\\"http://wwww.attestation.id\\\",\\\"version\\\":\\\"0.1\\\"}}\"}";
    Eip712AttestationRequest eiprequest = new Eip712AttestationRequest("http://wwww.attestation.id",
        request);
    assertTrue(eiprequest.verify());
    assertTrue(eiprequest.checkValidity());
  }

  @Test
  public void referenceJsonFormat() {
    String request = "{\"signatureInHex\":\"0x439cfdc3422621c1a77ad12bdf19e80876ddd7317b59055f352fe8d03a3dabba64c1a628321997b260658b098b490f6455c8724bffa859ec191d248a9e5015de1b\",\"jsonSigned\":\"{\\\"types\\\":{\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"}],\\\"AttestationRequest\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"}]},\\\"primaryType\\\":\\\"AttestationRequest\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIIBAgIBATCB_ARBBBmSwTCP4VSOr07WYbuIZjR6oUIigLCB-o_ygrN2b2xxHKXEocXBQM3NLqQ5OkRuj0ogmOpKgwn7LhWYWkqNzvMEICJmtJRx1tdMmkl2aurO3CCzauIr2G3rsR0VoUkub2M6BEEECsnXLNQdO2PgaHzQWGWg4KAQ4IvSkn1hPJotLPXMhPIuZeSry7aaOEQt64wyXUolp8an18193r5MKhfZ-E3AjQRSMFg3QTE4MUNCNzI1MDc3NkUxNjc4M0Y5RDNDOTE2NkRFMEY5NUFCMjgzr4crx6TxqXpXW2o9byWM8Ya4h7ATlfLav-aSz8hWQ8YAAAF41bojKA==\\\",\\\"description\\\":\\\"Linking Ethereum address to phone or email\\\",\\\"timestamp\\\":\\\"Thu Apr 15 2021 15:30:49 GMT+0200\\\",\\\"identifier\\\":\\\"test@test.ts\\\"},\\\"domain\\\":{\\\"name\\\":\\\"http://www.hotelbogota.com\\\",\\\"version\\\":\\\"0.1\\\"}}\"}";
    Eip712AttestationRequest eiprequest = new Eip712AttestationRequest(DOMAIN, Timestamp.UNLIMITED,
        request, new Eip712AttestationRequestEncoder(Eip712AttestationRequestEncoder.LEGACY_USAGE_VALUE));
    assertTrue(eiprequest.verify());
    assertTrue(eiprequest.checkValidity());
  }

  @Test
  public void testSunshine() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, attRequest, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
  }

  @Test
  public void testDecoding() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, attRequest, userSigningKey);
    Eip712AttestationRequest newRequest = new Eip712AttestationRequest(DOMAIN, request.getJsonEncoding());
    assertTrue(newRequest.verify());
    assertTrue(newRequest.checkValidity());

    assertTrue(AttestationCrypto.verifyFullProof(newRequest.getPok()));
    assertArrayEquals(request.getPok().getDerEncoding(), newRequest.getPok().getDerEncoding());
    assertEquals(request.getJsonEncoding(), newRequest.getJsonEncoding());
    assertEquals(request.getType(), newRequest.getType());
    ECKeyParameters requestPubKey = (ECKeyParameters) request.getUserPublicKey();
    ECKeyParameters newRequestPubKey = ((ECKeyParameters) newRequest.getUserPublicKey());
    assertTrue(Objects.deepEquals(requestPubKey.getParameters(), newRequestPubKey.getParameters()));
  }

  @Test
  public void testOtherValues() {
    AsymmetricCipherKeyPair otherKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    byte[] nonce = Nonce.makeNonce(SignatureUtility.addressFromKey(otherKeys.getPublic()), "https://www.othersite.org", new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(new BigInteger("623784673234325341563416"), nonce);
    AttestationRequest attRequest = new AttestationRequest(AttestationType.PHONE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest("https://www.othersite.org",
        "0015058081234", attRequest, otherKeys.getPrivate());
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
  }

  @Test
  public void eipEncoding() throws Exception {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, attRequest, userSigningKey);
    Eip712Test.validateEncoding(encoder, request.getJsonEncoding());
  }

  @Test
  public void eipSignableEncoding() throws Exception {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    AttestationRequestInternalData data = new AttestationRequestInternalData(
        encoder.getUsageValue(),
        MAIL, URLUtility.encodeData(attRequest.getDerEncoding()), new Timestamp());
    Eip712Signer issuer = new Eip712Signer<AttestationRequestInternalData>(userSigningKey, encoder);
    String json = issuer.buildSignedTokenFromJsonObject(data.getSignableVersion(), DOMAIN);
    Eip712Test.validateEncoding(encoder, json);
  }

  @Mock
  Eip712AttestationRequestEncoder mockedEncoder;
  @Test
  public void badDescription() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, attRequest, userSigningKey);
    Eip712AttestationRequestEncoder encoder = new Eip712AttestationRequestEncoder(Eip712AttestationRequestEncoder.LEGACY_USAGE_VALUE);
    mockedEncoder = spy(encoder);
    Mockito.when(mockedEncoder.getUsageValue()).thenReturn("Something wrong");
    Eip712AttestationRequest badRequest = new Eip712AttestationRequest(DOMAIN, Timestamp.DEFAULT_TIME_LIMIT_MS, request.getJsonEncoding(), mockedEncoder);
    assertTrue(badRequest.verify());
    assertFalse(badRequest.checkValidity());
  }

  @Test
  public void automaticDecoder() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, Timestamp.DEFAULT_TIME_LIMIT_MS,
        MAIL, attRequest, userSigningKey, new Eip712AttestationRequestEncoder(Eip712AttestationRequestEncoder.LEGACY_USAGE_VALUE));
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
    Eip712AttestationRequest decodedRequest = Eip712AttestationRequest.decodeAndValidateAttestation(DOMAIN, request.getJsonEncoding());
    assertTrue(decodedRequest.verify());
    assertTrue(decodedRequest.checkValidity());
    assertEquals(request.getJsonEncoding(), decodedRequest.getJsonEncoding());
  }

  @Test
  public void badDomain() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL,
        attRequest, userSigningKey);
    assertTrue(request.checkValidity());
    assertTrue(request.verify());
    Eip712AttestationRequest newRequest = new Eip712AttestationRequest("http://www.someOtherDomain.com", request.getJsonEncoding());
    assertTrue(newRequest.verify());
    assertFalse(newRequest.checkValidity());
  }

  @Test
  public void invalidDomain() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    assertThrows( RuntimeException.class, () ->  new Eip712AttestationRequest("www.noHttpPrefix", MAIL,
        attRequest, userSigningKey));
  }

  @Mock
  AttestationRequest mockAttestationRequest;
  @Test
  public void invalidConstructor() {
    Mockito.when(mockAttestationRequest.getDerEncoding()).thenReturn(null);
    Exception e = assertThrows( RuntimeException.class, () ->  new Eip712AttestationRequest(DOMAIN, MAIL, mockAttestationRequest,
        userSigningKey));
    assertEquals(e.getMessage(), "Could not encode object");
  }

  @Test
  public void invalidDomainOtherConstructor() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, attRequest,
        userSigningKey);
    assertThrows( RuntimeException.class, () ->  new Eip712AttestationRequest("www.noHttpPrefix", request.getJsonEncoding()));
  }

  @Test
  public void invalidAttestationRequest() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    Mockito.when(mockAttestationRequest.verify()).thenReturn(false);
    Mockito.when(mockAttestationRequest.getDerEncoding()).thenReturn(new byte[] {0x00});
    Mockito.when(mockAttestationRequest.getPok()).thenReturn(pok);
    Mockito.when(mockAttestationRequest.getType()).thenReturn(TYPE);
    assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequest(DOMAIN, MAIL,
        mockAttestationRequest, userSigningKey));
  }

  @Test
  public void invalidAttestationRequestOtherConstructor() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    Mockito.when(mockAttestationRequest.verify()).thenReturn(false);
    Mockito.when(mockAttestationRequest.getDerEncoding()).thenReturn(new byte[] {0x00});
    Mockito.when(mockAttestationRequest.getPok()).thenReturn(pok);
    Mockito.when(mockAttestationRequest.getType()).thenReturn(TYPE);
    assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequest(DOMAIN, MAIL,
        mockAttestationRequest, userSigningKey));
  }

  @Test
  public void badObject() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL,
        attRequest, userSigningKey);
    String json = request.getJsonEncoding();
    String newJson = json.replace(',', '.');
    Exception e = assertThrows(IllegalArgumentException.class,
        () -> new Eip712AttestationRequest(DOMAIN, newJson));
    assertEquals(e.getMessage(), "Could not decode object");
  }

  @Test
  public void invalidTimestamp() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp(10000));
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, attRequest, userSigningKey);
    assertFalse(request.checkValidity());
  }

  @Test
  public void invalidDomainConstructor() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Exception e = assertThrows(IllegalArgumentException.class,
        () -> new Eip712AttestationRequest("www.nohttp.com", MAIL,
            attRequest, userSigningKey));
    assertEquals(e.getMessage(), "Issuer domain is not a valid domain");
  }

  @Test
  public void invalidNonce() {
    byte[] wrongNonce = Nonce.makeNonce(userAddress, "http://www.notTheRightHotel.com", new Timestamp());
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, wrongPok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, attRequest,
        userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }

  @Test
  public void invalidEncoder() {
    byte[] nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, Timestamp.DEFAULT_TIME_LIMIT_MS,
        MAIL, attRequest, userSigningKey, new Eip712AttestationRequestEncoder(Eip712AttestationRequestEncoder.LEGACY_USAGE_VALUE));
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
    // Decode with wrong encoder
    Eip712AttestationRequest decodedRequest = new Eip712AttestationRequest(DOMAIN, Timestamp.DEFAULT_TIME_LIMIT_MS,
        request.getJsonEncoding(), new Eip712AttestationRequestEncoder(Eip712AttestationRequestEncoder.LISCON_USAGE_VALUE));
    assertTrue(decodedRequest.verify());
    assertFalse(decodedRequest.checkValidity());
  }

}
