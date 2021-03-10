package com.alphawallet.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestationRequest;
import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.Nonce;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

public class TestAttestationRequestEip712 {
  private static final String DOMAIN = "http://www.hotelbogota.com";
  private static final String MAIL = "test@test.ts";
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");
  private static final AttestationType TYPE = AttestationType.EMAIL;

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
    String json = request.getJsonEncoding();
    ObjectMapper mapper = new ObjectMapper();
    Eip712AttestationRequestEncoder encoder = new Eip712AttestationRequestEncoder();
    JsonNode message = mapper.readTree(mapper.readTree(json).get("jsonSigned").asText()).get("message");
    // Verify that all elements in the message got encoded
    for (Entry currentEntry : encoder.getTypes().get(encoder.getPrimaryName())) {
      JsonNode node = message.get(currentEntry.getName());
      assertNotNull(node);
      assertTrue(node.asText().length() > 0);
    }
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
        attRequest, userSigningKey, userAddress);
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
