package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import java.math.BigInteger;
import java.security.SecureRandom;

import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class ProofOfKnowledgeTest {

  public static final BigInteger SECRET1 = new BigInteger("5848910840846872525745834000448648789786746461");
  public static final BigInteger SECRET2 = new BigInteger("640848948534656666878789789789484891065000");
  public static final String ID = "test@test.ts";
  public static final byte[] NONCE = new byte[] {0x66};

  private static AttestationCrypto crypto;
  private static SecureRandom rand;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
  }


  @Test
  public void TestSunshineAttestationProof() {
    FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.TEN);
    assertTrue(crypto.verifyFullProof(pok));
    FullProofOfExponent newPok = new FullProofOfExponent(pok.getDerEncoding());
    assertTrue(crypto.verifyFullProof(newPok));
    assertEquals(pok.getRiddle(), newPok.getRiddle());
    assertEquals(pok.getPoint(), newPok.getPoint());
    assertEquals(pok.getChallenge(), newPok.getChallenge());
    assertArrayEquals(pok.getNonce(), newPok.getNonce());
    assertArrayEquals(pok.getDerEncoding(), newPok.getDerEncoding());

    FullProofOfExponent newConstructor = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallenge(), pok.getNonce());
    assertArrayEquals(pok.getDerEncoding(), newConstructor.getDerEncoding());
  }

  @Test
  public void TestSunshineAttestationProofWithNonce() {
    FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.ONE, NONCE);
    assertTrue(crypto.verifyFullProof(pok));
    FullProofOfExponent newPok = new FullProofOfExponent(pok.getDerEncoding());
    assertTrue(crypto.verifyFullProof(newPok));
    assertEquals(pok.getRiddle(), newPok.getRiddle());
    assertEquals(pok.getPoint(), newPok.getPoint());
    assertEquals(pok.getChallenge(), newPok.getChallenge());
    assertArrayEquals(pok.getNonce(), newPok.getNonce());
    assertArrayEquals(pok.getDerEncoding(), newPok.getDerEncoding());

    FullProofOfExponent newConstructor = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallenge(), pok.getNonce());
    assertArrayEquals(pok.getDerEncoding(), newConstructor.getDerEncoding());
  }

  @Test
  public void TestNegativeAttestationProof() {
    FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.TEN, NONCE);
    assertTrue(crypto.verifyFullProof(pok));
    FullProofOfExponent newPok;
    newPok = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE), pok.getNonce());
    assertFalse(crypto.verifyFullProof(newPok));
    newPok = new FullProofOfExponent(pok.getRiddle(), pok.getPoint().multiply(new BigInteger("2")), pok.getChallenge(), pok.getNonce());
    assertFalse(crypto.verifyFullProof(newPok));
    newPok = new FullProofOfExponent(pok.getRiddle().multiply(new BigInteger("2")), pok.getPoint(), pok.getChallenge(), pok.getNonce());
    assertFalse(crypto.verifyFullProof(newPok));
    byte[] nonce = newPok.getNonce();
    nonce[0] ^= 0x01;
    newPok = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallenge(), nonce);
    assertFalse(crypto.verifyFullProof(newPok));
  }

  @Test
  public void TestSunshineEqualityProof() throws Exception {
    byte[] com1 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET1);
    byte[] com2 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET2);
    ProofOfExponent pok = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2, NONCE);
    assertTrue(crypto.verifyEqualityProof(com1, com2, pok));
    UsageProofOfExponent newPok = new UsageProofOfExponent(pok.getDerEncoding());
    assertTrue(crypto.verifyEqualityProof(com1, com2, newPok));
    assertEquals(pok.getPoint(), newPok.getPoint());
    assertEquals(pok.getChallenge(), newPok.getChallenge());
    assertArrayEquals(pok.getNonce(), newPok.getNonce());
    assertArrayEquals(pok.getDerEncoding(), newPok.getDerEncoding());

    ProofOfExponent newConstructorWONonce = new UsageProofOfExponent(pok.getPoint(), pok.getChallenge());
    assertFalse(Arrays.equals(pok.getDerEncoding(), newConstructorWONonce.getDerEncoding()));
    ProofOfExponent newConstructorWithNonce = new UsageProofOfExponent(pok.getPoint(), pok.getChallenge(), pok.getNonce());
    assertArrayEquals(pok.getDerEncoding(), newConstructorWithNonce.getDerEncoding());
  }

  @Test
  public void TestNegativeEqualityProof() {
    byte[] com1 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET1);
    byte[] com2 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET2);
    ProofOfExponent pok = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2);
    assertTrue(crypto.verifyEqualityProof(com1, com2, pok));
    ProofOfExponent newPok;
    newPok = new UsageProofOfExponent(pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
    assertFalse(crypto.verifyEqualityProof(com1, com2, newPok));
    newPok = new UsageProofOfExponent(pok.getPoint().multiply(new BigInteger("2")), pok.getChallenge());
    assertFalse(crypto.verifyEqualityProof(com1, com2, newPok));
  }
}
