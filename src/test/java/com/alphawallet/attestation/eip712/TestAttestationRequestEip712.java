package com.alphawallet.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.Nonce;
import com.alphawallet.attestation.core.SignatureUtility;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestAttestationRequestEip712 {
  private static final String DOMAIN = "http://www.hotelbogota.com";
  private static final String MAIL = "test@test.ts";
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");

  private static AsymmetricCipherKeyPair userKeys;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

  @Test
  public void testSunshine() {
    byte[] nonce = Nonce.makeNonce(MAIL, SignatureUtility.addressFromKey(userKeys.getPublic()), DOMAIN,
        Clock.systemUTC().millis());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, AttestationType.EMAIL, pok, userKeys);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
  }

  @Test
  public void testDecoding() {
    byte[] nonce = Nonce.makeNonce(MAIL, SignatureUtility.addressFromKey(userKeys.getPublic()), DOMAIN,
        Clock.systemUTC().millis());
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, AttestationType.EMAIL, pok, userKeys);
    Eip712AttestationRequest newRequest = new Eip712AttestationRequest(DOMAIN, request.getJsonEncoding());
    assertTrue(newRequest.verify());
    assertTrue(newRequest.checkValidity());

    assertTrue(AttestationCrypto.verifyAttestationRequestProof(newRequest.getPok()));
    assertArrayEquals(request.getPok().getDerEncoding(), newRequest.getPok().getDerEncoding());
    assertEquals(request.getJsonEncoding(), newRequest.getJsonEncoding());
    assertEquals(request.getType(), newRequest.getType());
    assertEquals( ((ECKeyParameters) request.getPublicKey()).getParameters(),
        ((ECKeyParameters) newRequest.getPublicKey()).getParameters());
    assertEquals(((ECKeyParameters) request.getPublicKey()).getParameters(),
        ((ECKeyParameters) userKeys.getPublic()).getParameters());
  }

  @Test
  public void badDomain() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL,
        AttestationType.EMAIL, pok, userKeys);
    assertThrows( IllegalArgumentException.class, () ->   new Eip712AttestationRequest("http://www.someOtherDomain.com", request.getJsonEncoding()));
  }

  @Test
  public void invalidDomain() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    assertThrows( RuntimeException.class, () ->  new Eip712AttestationRequest("www.noHttpPrefix", MAIL, AttestationType.EMAIL, pok, userKeys));
  }

  @Test
  public void invalidDomainOtherConstructor() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, AttestationType.EMAIL, pok, userKeys);
    assertThrows( RuntimeException.class, () ->  new Eip712AttestationRequest("www.noHttpPrefix", request.getJsonEncoding()));
  }

  @Test
  public void invalidAttestationRequest() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    FullProofOfExponent badPok = new FullProofOfExponent(
        pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
    assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequest(DOMAIN, MAIL, AttestationType.EMAIL, badPok, userKeys));
  }

  @Test
  public void invalidAttestationRequestOtherConstructor() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    FullProofOfExponent badPok = new FullProofOfExponent(
        pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
    assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequest(DOMAIN, MAIL, AttestationType.EMAIL, badPok, userKeys));
  }

  @Test
  public void badSignature() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL,
        AttestationType.EMAIL, pok, userKeys);
    byte[] encoding = request.getJsonEncoding().getBytes(StandardCharsets.UTF_8);
    // Flip a bit in the signature part of the encoding
    encoding[40] ^= 0x01;
    assertThrows(IllegalArgumentException.class,
        () -> new Eip712AttestationRequest(DOMAIN, new String(encoding)));
  }

  @Test
  public void invalidTimestamp() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, -100, MAIL,
        AttestationType.EMAIL, pok, userKeys);
    assertFalse(request.checkValidity());
  }

  @Test
  public void invalidNonce() {
    byte[] wrongNonce = Nonce.makeNonce(MAIL, SignatureUtility.addressFromKey(userKeys.getPublic()), "http://www.notTheRightHotel.com",
        Clock.systemUTC().millis());
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, AttestationType.EMAIL, wrongPok, userKeys);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }

}
