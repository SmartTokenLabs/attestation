package com.alphawallet.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestationRequest;
import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.Nonce;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.eip712.Eip712AttestationRequestEncoder.AttestationRequestInternalData;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.tokenscript.eip712.Eip712Issuer;
import org.tokenscript.eip712.Eip712Test;

public class TestAttestationRequestEip712 {
  private static final String DOMAIN = "http://www.hotelbogota.com";
  private static final String MAIL = "test@test.ts";
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");
  private static final AttestationType TYPE = AttestationType.EMAIL;
  private static final long CHAIN_ID = 1;

  private static AsymmetricKeyParameter userSigningKey;
  private static String userAddress;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
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

  @Test
  public void validateJSToken() {
    String request = "{\"signatureInHex\":\"0x6e2a95d19eb26e8a01b11d4ea694387a97f64030c880e0fd96b8378b913b4ec1632335d42781185cbd1044e6706eec1d08dafb063f86a47bf19b10faa85e07781c\",\"jsonRpc\":\"2.0\",\"chainId\":3,\"jsonSigned\":\"{\\\"domain\\\":{\\\"chainId\\\":3,\\\"name\\\":\\\"http://wwww.attestation.id\\\",\\\"version\\\":\\\"0.1\\\"},\\\"message\\\":{\\\"payload\\\":\\\"MIIBLQIBADCCASYEQQQjSSuHoeDrfflLEOw95Vc0kZHB6cz3pxpVsT6wgYXQaB9UHrziOybmB9Og6cD86Du1nP333I3k5vUogUa_9n5NBCADa4wSP3noAIpweaXuCgNJQGWIikjZiisEjFKg7SS_UQRBBAze02glDx9vj1SU6EDo3oNYR-qRam7m_tzhPffMchQgLTEM6Cf1hyytuly5ZfbhTyLKb90cTqw1QIoDIqn8W6AEfAAAAXhA_G5sdH-jiuhdX2vhv-GKUEDz1PufxLdKSXLUQOe9y48bbCgvIdwS3UO9FbhmQzMgQauXAQNX16mVOdMvZKl24jVJjabMI6iY8lztbg-HkIsPKqDcH4B8xdJGAYb3IzySfn2y3McDwOUAtlPKgic7e_rYBF2FpHA=\\\",\\\"description\\\":\\\"Linking Ethereum address to phone or email\\\",\\\"timestamp\\\":\\\"Wed Mar 17 2021 18:19:49 GMT+0200\\\",\\\"identifier\\\":\\\"test@test.com\\\",\\\"address\\\":\\\"0x2f21dc12dd43bd15b86643332041ab97010357d7\\\"},\\\"primaryType\\\":\\\"AttestationRequest\\\",\\\"types\\\":{\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"}],\\\"AttestationRequest\\\":[{\\\"name\\\":\\\"address\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"}]}}\"}";
    Eip712AttestationRequest eiprequest = new Eip712AttestationRequest("http://wwww.attestation.id", 1000*60*60*24*365*10,3, request);
    assertTrue(eiprequest.verify());
    assertTrue(eiprequest.checkValidity());
  }

  @Test
  public void testSunshine() {
    byte[] nonce = Nonce.makeNonce(MAIL, userAddress, DOMAIN, Clock.systemUTC().millis());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, attRequest, userSigningKey, userAddress);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
  }

  @Test
  public void testDecoding() {
    byte[] nonce = Nonce.makeNonce(MAIL, userAddress, DOMAIN, Clock.systemUTC().millis());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, attRequest, userSigningKey, userAddress);
    Eip712AttestationRequest newRequest = new Eip712AttestationRequest(DOMAIN, request.getJsonEncoding());
    assertTrue(newRequest.verify());
    assertTrue(newRequest.checkValidity());

    assertTrue(AttestationCrypto.verifyFullProof(newRequest.getPok()));
    assertArrayEquals(request.getPok().getDerEncoding(), newRequest.getPok().getDerEncoding());
    assertEquals(request.getJsonEncoding(), newRequest.getJsonEncoding());
    assertEquals(request.getType(), newRequest.getType());
    assertEquals( ((ECKeyParameters) request.getPublicKey()).getParameters(),
        ((ECKeyParameters) newRequest.getPublicKey()).getParameters());
  }

  @Test
  public void eipEncoding() throws Exception {
    byte[] nonce = Nonce.makeNonce(MAIL, userAddress, DOMAIN, Clock.systemUTC().millis());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, attRequest, userSigningKey, userAddress);
    Eip712Test.validateEncoding(new Eip712AttestationRequestEncoder(CHAIN_ID), request.getJsonEncoding());
  }

  @Test
  public void eipSignableEncoding() throws Exception {
    byte[] nonce = Nonce.makeNonce(MAIL, userAddress, DOMAIN, Clock.systemUTC().millis());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    AttestationRequestInternalData data = new AttestationRequestInternalData(
        Eip712AttestationRequestEncoder.USAGE_VALUE,
        MAIL, userAddress, URLUtility.encodeData(attRequest.getDerEncoding()), Clock.systemUTC().millis());
    Eip712Issuer issuer = new Eip712Issuer<AttestationRequestInternalData>(userSigningKey, new Eip712AttestationRequestEncoder(CHAIN_ID));
    String json = issuer.buildSignedTokenFromJsonObject(data.getSignableVersion(), DOMAIN);
    Eip712Test.validateEncoding(new Eip712AttestationRequestEncoder(CHAIN_ID), json);
  }

  @Test
  public void badDomain() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL,
        attRequest, userSigningKey, userAddress);
    assertThrows( IllegalArgumentException.class, () ->   new Eip712AttestationRequest("http://www.someOtherDomain.com", request.getJsonEncoding()));
  }

  @Test
  public void invalidDomain() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    assertThrows( RuntimeException.class, () ->  new Eip712AttestationRequest("www.noHttpPrefix", MAIL,
        attRequest, userSigningKey, userAddress));
  }

  @Test
  public void invalidDomainOtherConstructor() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, attRequest,
        userSigningKey, userAddress);
    assertThrows( RuntimeException.class, () ->  new Eip712AttestationRequest("www.noHttpPrefix", request.getJsonEncoding()));
  }

  @Mock
  AttestationRequest mockAttestationRequest;
  @Test
  public void invalidAttestationRequestOtherConstructor() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    Mockito.when(mockAttestationRequest.verify()).thenReturn(false);
    Mockito.when(mockAttestationRequest.getDerEncoding()).thenReturn(new byte[] {0x00});
    Mockito.when(mockAttestationRequest.getPok()).thenReturn(pok);
    Mockito.when(mockAttestationRequest.getType()).thenReturn(TYPE);
    assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequest(DOMAIN, MAIL,
        mockAttestationRequest, userSigningKey, userAddress));
  }

  @Test
  public void badSignature() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL,
        attRequest, userSigningKey, userAddress);
    byte[] encoding = request.getJsonEncoding().getBytes(StandardCharsets.UTF_8);
    // Flip a bit in the signature part of the encoding
    encoding[40] ^= 0x01;
    assertThrows(IllegalArgumentException.class,
        () -> new Eip712AttestationRequest(DOMAIN, new String(encoding)));
  }

  @Test
  public void invalidTimestamp() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    AttestationRequest attRequest = new AttestationRequest(TYPE, pok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, -100, MAIL,
        attRequest, userSigningKey, userAddress, CHAIN_ID);
    assertFalse(request.checkValidity());
  }

  @Test
  public void invalidNonce() {
    byte[] wrongNonce = Nonce.makeNonce(MAIL, userAddress, "http://www.notTheRightHotel.com",
        Clock.systemUTC().millis());
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    AttestationRequest attRequest = new AttestationRequest(TYPE, wrongPok);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, attRequest,
        userSigningKey, userAddress);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }


}
