package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.apache.logging.log4j.core.util.Assert;
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
    ProofOfExponent pok = crypto.constructProof(id, type, secret);
    AttestationRequest request = new AttestationRequest(id, type, pok, subjectKeys);
    assertTrue(request.getPok().verify());
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
  }

  @Test
  public void testDecoding() {
    String id = "foo@bar.baz";
    AttestationType type = AttestationType.EMAIL;
    BigInteger secret = new BigInteger("42424242");
    ProofOfExponent pok = crypto.constructProof(id, type, secret);
    AttestationRequest request = new AttestationRequest(id, type, pok, subjectKeys);
    AttestationRequest newRequest = new AttestationRequest(request.getDerEncoding());
    assertTrue(newRequest.getPok().verify());
    assertTrue(newRequest.verify());
    assertTrue(newRequest.checkValidity());
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
  public void testNormalizingID() {
    AttestationType type = AttestationType.EMAIL;
    BigInteger secret = new BigInteger("154160516004573454304564685743521");
    ProofOfExponent pok = crypto.constructProof("foo@bar.baz", type, secret);
    AttestationRequest request = new AttestationRequest(" foO@BAr.baz     ", type, pok, subjectKeys);
    // The IDs should be equivalent to avoid impersonation
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
  }

  @Test
  public void testBadID() {
    AttestationType type = AttestationType.EMAIL;
    BigInteger secret = new BigInteger("42424242");
    ProofOfExponent pok = crypto.constructProof("foo@bar.baz", type, secret);
    AttestationRequest request = new AttestationRequest("foo@bar.bazt", type, pok, subjectKeys);
    assertTrue(request.verify()); // Signature and proof are ok by themselves
    assertFalse(request.checkValidity()); // However, the proof is not done over the right id
  }

  @Test
  public void testBadType() {
    String id = "foo@bar.baz";
    BigInteger secret = new BigInteger("42424242");
    ProofOfExponent pok = crypto.constructProof(id, AttestationType.EMAIL, secret);
    AttestationRequest request = new AttestationRequest(id, AttestationType.PHONE, pok, subjectKeys);
    assertTrue(request.verify()); // Signature and proof are ok by themselves
    assertFalse(request.checkValidity()); // However, the proof is not done over the right type
  }
}
