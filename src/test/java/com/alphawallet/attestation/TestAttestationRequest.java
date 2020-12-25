package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestAttestationRequest {
  private static AsymmetricCipherKeyPair subjectKeys;
  private static AttestationCrypto crypto;

  @BeforeAll
  public static void setupKeys() throws Exception {
    SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    crypto = new AttestationCrypto(rand);
    subjectKeys = crypto.constructECKeys();
  }

  @Test
  public void testSunshine() {
    String id = "+4588888888";
    AttestationType type = AttestationType.PHONE;
    BigInteger secret = new BigInteger("42");
    ProofOfExponent pok = crypto.computeAttestationProof(secret);
    AttestationRequest request = new AttestationRequest(id, type, pok, subjectKeys);
    assertTrue(AttestationCrypto.verifyAttestationRequestProof(request.getPok()));
    assertTrue(request.verify());
  }

  @Test
  public void testDecoding() {
    String id = "foo@bar.baz";
    AttestationType type = AttestationType.EMAIL;
    BigInteger secret = new BigInteger("42424242");
    ProofOfExponent pok = crypto.computeAttestationProof(secret);
    AttestationRequest request = new AttestationRequest(id, type, pok, subjectKeys);
    AttestationRequest newRequest = new AttestationRequest(request.getDerEncoding());
    assertTrue(AttestationCrypto.verifyAttestationRequestProof(newRequest.getPok()));
    assertTrue(newRequest.verify());
    assertArrayEquals(request.getPok().getDerEncoding(), newRequest.getPok().getDerEncoding());
    assertArrayEquals(request.getDerEncoding(), newRequest.getDerEncoding());
    assertArrayEquals(request.getSignature(), newRequest.getSignature());
    assertEquals(request.getIdentity(), newRequest.getIdentity());
    assertEquals(request.getIdentity(), id);
    assertEquals(request.getType(), newRequest.getType());
    assertEquals(request.getType(), type);
    assertEquals( ((ECKeyParameters) request.getPublicKey()).getParameters(),
        ((ECKeyParameters) newRequest.getPublicKey()).getParameters());
    assertEquals(((ECKeyParameters) request.getPublicKey()).getParameters(),
        ((ECKeyParameters) subjectKeys.getPublic()).getParameters());
  }

  @Test
  public void testBadSig() {
    String id = "+4588888888";
    AttestationType type = AttestationType.PHONE;
    BigInteger secret = new BigInteger("42");
    ProofOfExponent pok = crypto.computeAttestationProof(secret);
    AttestationRequest request = new AttestationRequest(id, type, pok, subjectKeys);
    // Modify a bit of the signature
    request.getSignature()[20] ^= 1;
    assertFalse(request.verify());
  }

}
