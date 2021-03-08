package com.alphawallet.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.IdentifierAttestation;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.SignedIdentityAttestation;
import com.alphawallet.attestation.UseAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.Nonce;
import com.alphawallet.attestation.core.SignatureUtility;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Clock;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestAttestationUsageEip712 {
  private static final String DOMAIN = "https://www.hotelbogota.com";
  private static final String MAIL = "email@test.com";
  private static final AttestationType TYPE = AttestationType.EMAIL;
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("15816808484023");

  private static byte[] nonce;
  private static FullProofOfExponent pok;
  private static SignedIdentityAttestation signedAttestation;
  private static AsymmetricCipherKeyPair attestorKeys;
  private static AsymmetricKeyParameter userSigningKey;
  private static String userAddress;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    attestorKeys = SignatureUtility.constructECKeys(SECNamedCurves.getByName("secp384r1"), rand);
    AsymmetricCipherKeyPair userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    userSigningKey = userKeys.getPrivate();
    userAddress = SignatureUtility.addressFromKey(userKeys.getPublic());
    nonce = Nonce.makeNonce(MAIL, userAddress, DOMAIN, Clock.systemUTC().millis());
    pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    IdentifierAttestation att = HelperTest
        .makeUnsignedStandardAtt(userKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    signedAttestation = new SignedIdentityAttestation(att, attestorKeys);
  }

  @Test
  public void testSunshine() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok);
    assertTrue(usage.verify());
    assertTrue(usage.checkValidity());
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
  }

  @Test
  public void testDecoding() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    Eip712AttestationUsage newRequest = new Eip712AttestationUsage(DOMAIN, userSigningKey, request.getJsonEncoding());
    assertTrue(newRequest.verify());
    assertTrue(newRequest.checkValidity());

    assertEquals(request.getIdentifier(), newRequest.getIdentifier());
    assertTrue(AttestationCrypto.verifyFullProof(newRequest.getPok()));
    assertArrayEquals(request.getPok().getDerEncoding(), newRequest.getPok().getDerEncoding());
    assertTrue(newRequest.getAttestation().verify());
    assertTrue(newRequest.getAttestation().checkValidity());
    assertArrayEquals(request.getAttestation().getDerEncoding(), newRequest.getAttestation().getDerEncoding());
    assertEquals(request.getJsonEncoding(), newRequest.getJsonEncoding());
    assertEquals(request.getType(), newRequest.getType());
    assertEquals( ((ECKeyParameters) request.getPublicKey()).getParameters(),
        ((ECKeyParameters) newRequest.getPublicKey()).getParameters());
  }
//
//  @Test
//  public void badDomain() {
//    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
//    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL,
//        AttestationType.EMAIL, pok,userSigningKey, userAddress);
//    assertThrows( IllegalArgumentException.class, () ->   new Eip712AttestationRequest("http://www.someOtherDomain.com", request.getJsonEncoding()));
//  }
//
//  @Test
//  public void invalidDomain() {
//    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
//    assertThrows( RuntimeException.class, () ->  new Eip712AttestationRequest("www.noHttpPrefix", MAIL, AttestationType.EMAIL, pok,
//        userSigningKey, userAddress));
//  }
//
//  @Test
//  public void invalidDomainOtherConstructor() {
//    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
//    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, AttestationType.EMAIL, pok,
//        userSigningKey, userAddress);
//    assertThrows( RuntimeException.class, () ->  new Eip712AttestationRequest("www.noHttpPrefix", request.getJsonEncoding()));
//  }
//
//  @Test
//  public void invalidAttestationRequest() {
//    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
//    FullProofOfExponent badPok = new FullProofOfExponent(
//        pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
//    assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequest(DOMAIN, MAIL, AttestationType.EMAIL, badPok,
//        userSigningKey, userAddress));
//  }
//
//  @Test
//  public void invalidAttestationRequestOtherConstructor() {
//    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
//    FullProofOfExponent badPok = new FullProofOfExponent(
//        pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
//    assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationRequest(DOMAIN, MAIL, AttestationType.EMAIL, badPok,
//        userSigningKey, userAddress));
//  }
//
//  @Test
//  public void badSignature() {
//    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
//    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL,
//        AttestationType.EMAIL, pok, userSigningKey, userAddress);
//    byte[] encoding = request.getJsonEncoding().getBytes(StandardCharsets.UTF_8);
//    // Flip a bit in the signature part of the encoding
//    encoding[40] ^= 0x01;
//    assertThrows(IllegalArgumentException.class,
//        () -> new Eip712AttestationRequest(DOMAIN, new String(encoding)));
//  }
//
//  @Test
//  public void invalidTimestamp() {
//    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
//    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, -100, MAIL,
//        AttestationType.EMAIL, pok, userSigningKey, userAddress);
//    assertFalse(request.checkValidity());
//  }
//
//  @Test
//  public void invalidNonce() {
//    byte[] wrongNonce = Nonce.makeNonce(MAIL, userAddress, "http://www.notTheRightHotel.com",
//        Clock.systemUTC().millis());
//    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
//    Eip712AttestationRequest request = new Eip712AttestationRequest(DOMAIN, MAIL, AttestationType.EMAIL, wrongPok,
//        userSigningKey, userAddress);
//    assertTrue(request.verify());
//    assertFalse(request.checkValidity());
//  }


}
