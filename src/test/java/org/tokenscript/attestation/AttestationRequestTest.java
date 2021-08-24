package org.tokenscript.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.SignatureUtility;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class AttestationRequestTest {
  private static AsymmetricCipherKeyPair subjectKeys;
  private static AttestationCrypto crypto;

  @BeforeAll
  public static void setupKeys() throws Exception {
    SecureRandom rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());

    crypto = new AttestationCrypto(rand);
    subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

  @Test
  public void testSunshine() {
    AttestationType type = AttestationType.PHONE;
    BigInteger secret = new BigInteger("42");
    FullProofOfExponent pok = crypto.computeAttestationProof(secret);
    AttestationRequest request = new AttestationRequest(type, pok);
    assertTrue(AttestationCrypto.verifyFullProof(request.getPok()));
    assertTrue(request.verify());
  }

  @Test
  public void testDecoding() {
    AttestationType type = AttestationType.EMAIL;
    BigInteger secret = new BigInteger("42424242");
    FullProofOfExponent pok = crypto.computeAttestationProof(secret);
    AttestationRequest request = new AttestationRequest(type, pok);
    AttestationRequest newRequest = new AttestationRequest(request.getDerEncoding());
    assertTrue(AttestationCrypto.verifyFullProof(newRequest.getPok()));
    assertTrue(newRequest.verify());
    assertArrayEquals(request.getPok().getDerEncoding(), newRequest.getPok().getDerEncoding());
    assertArrayEquals(request.getDerEncoding(), newRequest.getDerEncoding());
    assertEquals(request.getType(), newRequest.getType());
    assertEquals(request.getType(), type);
  }


}
