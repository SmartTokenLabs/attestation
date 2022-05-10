package org.tokenscript.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.core.AttestationCrypto;
import java.math.BigInteger;
import java.security.SecureRandom;

import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class ProofOfKnowledgeTest {

  public static final BigInteger SECRET1 = new BigInteger("5848910840846872525745834000448648789786746461");
  public static final BigInteger SECRET2 = new BigInteger("640848948534656666878789789789484891065000");
  public static final String ID = "test@test.ts";
  public static final byte[] UN = new byte[] {0x66};

  private static AttestationCrypto crypto;
  private static SecureRandom rand;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
  }


  @Test
  public void TestSunshineAttestationProof() {
    FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.TEN);
    assertTrue(crypto.verifyFullProof(pok));
    FullProofOfExponent newPok = new FullProofOfExponent(pok.getDerEncoding());
    assertTrue(crypto.verifyFullProof(newPok));
    assertTrue(newPok.validateParameters());
    assertEquals(pok.getRiddle(), newPok.getRiddle());
    assertEquals(pok.getPoint(), newPok.getPoint());
    assertEquals(pok.getChallengeResponse(), newPok.getChallengeResponse());
    assertArrayEquals(pok.getUnpredictableNumber(), newPok.getUnpredictableNumber());
    assertArrayEquals(pok.getDerEncoding(), newPok.getDerEncoding());

    FullProofOfExponent newConstructor = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallengeResponse(), pok.getUnpredictableNumber());
    assertArrayEquals(pok.getDerEncoding(), newConstructor.getDerEncoding());
  }

  @Test
  public void TestSunshineAttestationProofWithUn() {
    FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.valueOf(2), UN);
    assertTrue(crypto.verifyFullProof(pok));
    FullProofOfExponent newPok = new FullProofOfExponent(pok.getDerEncoding());
    assertTrue(crypto.verifyFullProof(newPok));
    assertTrue(newPok.validateParameters());
    assertEquals(pok.getRiddle(), newPok.getRiddle());
    assertEquals(pok.getPoint(), newPok.getPoint());
    assertEquals(pok.getChallengeResponse(), newPok.getChallengeResponse());
    assertArrayEquals(pok.getUnpredictableNumber(), newPok.getUnpredictableNumber());
    assertArrayEquals(pok.getDerEncoding(), newPok.getDerEncoding());

    FullProofOfExponent newConstructor = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallengeResponse(), pok.getUnpredictableNumber());
    assertArrayEquals(pok.getDerEncoding(), newConstructor.getDerEncoding());
  }

  @Test
  public void TestNegativeAttestationProof() {
    FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.TEN, UN);
    assertTrue(crypto.verifyFullProof(pok));
    FullProofOfExponent newPok;
    newPok = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallengeResponse().add(BigInteger.ONE), pok.getUnpredictableNumber());
    assertFalse(crypto.verifyFullProof(newPok));
    newPok = new FullProofOfExponent(pok.getRiddle(), pok.getPoint().multiply(new BigInteger("2")), pok.getChallengeResponse(), pok.getUnpredictableNumber());
    assertFalse(crypto.verifyFullProof(newPok));
    newPok = new FullProofOfExponent(pok.getRiddle().multiply(new BigInteger("2")), pok.getPoint(), pok.getChallengeResponse(), pok.getUnpredictableNumber());
    assertFalse(crypto.verifyFullProof(newPok));
    byte[] un = newPok.getUnpredictableNumber();
    un[0] ^= 0x01;
    newPok = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallengeResponse(), un);
    assertFalse(crypto.verifyFullProof(newPok));
  }

  @Test
  public void TestSunshineEqualityProof() throws Exception {
    byte[] com1 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET1);
    byte[] com2 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET2);
    ProofOfExponent pok = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2, UN);
    assertTrue(crypto.verifyEqualityProof(com1, com2, pok));
    UsageProofOfExponent newPok = new UsageProofOfExponent(pok.getDerEncoding());
    assertTrue(crypto.verifyEqualityProof(com1, com2, newPok));
    assertTrue(newPok.validateParameters());
    assertEquals(pok.getPoint(), newPok.getPoint());
    assertEquals(pok.getChallengeResponse(), newPok.getChallengeResponse());
    assertArrayEquals(pok.getUnpredictableNumber(), newPok.getUnpredictableNumber());
    assertArrayEquals(pok.getDerEncoding(), newPok.getDerEncoding());

    ProofOfExponent newConstructorWOUn = new UsageProofOfExponent(pok.getPoint(), pok.getChallengeResponse());
    assertFalse(Arrays.equals(pok.getDerEncoding(), newConstructorWOUn.getDerEncoding()));
    ProofOfExponent newConstructorWithUn = new UsageProofOfExponent(pok.getPoint(), pok.getChallengeResponse(), pok.getUnpredictableNumber());
    assertArrayEquals(pok.getDerEncoding(), newConstructorWithUn.getDerEncoding());
  }

  @Test
  public void TestNegativeEqualityProof() {
    byte[] com1 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET1);
    byte[] com2 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET2);
    ProofOfExponent pok = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2);
    assertTrue(crypto.verifyEqualityProof(com1, com2, pok));
    ProofOfExponent newPok;
    newPok = new UsageProofOfExponent(pok.getPoint(), pok.getChallengeResponse().add(BigInteger.ONE));
    assertFalse(crypto.verifyEqualityProof(com1, com2, newPok));
    assertTrue(newPok.validateParameters());
    newPok = new UsageProofOfExponent(pok.getPoint().multiply(new BigInteger("2")), pok.getChallengeResponse());
    assertFalse(crypto.verifyEqualityProof(com1, com2, newPok));
    assertTrue(newPok.validateParameters());
  }

  @ParameterizedTest
  @ValueSource(strings = {"-16000", "-1", "0", "1000000000000000000000000000000000000000000000000000000000000000000000000000000000"})
  public void negativeChallengeResponsesFullPoK(String challengeResponse) {
    FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.TEN, UN);
    FullProofOfExponent pokWithWrongChallengeResp = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), new BigInteger(challengeResponse));
    assertFalse(pokWithWrongChallengeResp.validateParameters());
  }

  @ParameterizedTest
  @ValueSource(strings = {"-16000", "-1", "0", "1000000000000000000000000000000000000000000000000000000000000000000000000000000000"})
  public void negativeChallengeResponsesUsagePoK(String challengeResponse) {
    byte[] com1 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET1);
    byte[] com2 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET2);
    UsageProofOfExponent pok = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2, UN);
    UsageProofOfExponent pokWithWrongChallengeResp = new UsageProofOfExponent(pok.getPoint(), new BigInteger(challengeResponse));
    assertFalse(pokWithWrongChallengeResp.validateParameters());
  }

  @Test
  public void generatorRiddleFullPoK() {
    FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.TEN, UN);
    FullProofOfExponent pokWithGen = new FullProofOfExponent(AttestationCrypto.G, pok.getPoint(), pok.getChallengeResponse());
    assertFalse(pokWithGen.validateParameters());
    // Try with other generator
    FullProofOfExponent pokWithOtherGen = new FullProofOfExponent(AttestationCrypto.H, pok.getPoint(), pok.getChallengeResponse());
    assertFalse(pokWithOtherGen.validateParameters());
  }

  @Test
  public void generatorTPointFullPoK() {
    FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.TEN, UN);
    FullProofOfExponent pokWithGen = new FullProofOfExponent(pok.getRiddle(), AttestationCrypto.G, pok.getChallengeResponse());
    assertFalse(pokWithGen.validateParameters());
    assertFalse(AttestationCrypto.verifyFullProof(pokWithGen));
    // Try with other generator
    FullProofOfExponent pokWithOtherGen = new FullProofOfExponent(pok.getRiddle(), AttestationCrypto.H, pok.getChallengeResponse());
    assertFalse(pokWithOtherGen.validateParameters());
    assertFalse(AttestationCrypto.verifyFullProof(pokWithOtherGen));
  }

  @Test
  public void generatorTPointUsagePoK() {
    byte[] com1 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET1);
    byte[] com2 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET2);
    UsageProofOfExponent pok = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2, UN);
    UsageProofOfExponent pokWithGen = new UsageProofOfExponent(AttestationCrypto.G, pok.getChallengeResponse());
    assertFalse(pokWithGen.validateParameters());
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, com2, pokWithGen));
    // Try with other generator
    UsageProofOfExponent pokWithOtherGen = new UsageProofOfExponent(AttestationCrypto.H, pok.getChallengeResponse());
    assertFalse(pokWithOtherGen.validateParameters());
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, com2, pokWithOtherGen));
  }

  @Test
  public void pointNotOnCurveFullPok() {
    FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.TEN, UN);
    ECPoint point = AttestationCrypto.curve.createPoint(new BigInteger("42"), new BigInteger("1337"));
    FullProofOfExponent pokNotOnCurve = new FullProofOfExponent(point, pok.getPoint(), pok.getChallengeResponse());
    assertFalse(pokNotOnCurve.validateParameters());
    assertFalse(AttestationCrypto.verifyFullProof(pokNotOnCurve));
    // Try with other generator
    FullProofOfExponent otherPokNotOnCurve = new FullProofOfExponent(pok.getRiddle(), point, pok.getChallengeResponse());
    assertFalse(otherPokNotOnCurve.validateParameters());
    assertFalse(AttestationCrypto.verifyFullProof(otherPokNotOnCurve));
  }

  @Test
  public void pointNotOnCurveUsagePok() {
    byte[] com1 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET1);
    byte[] com2 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET2);
    UsageProofOfExponent pok = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2, UN);
    ECPoint point = AttestationCrypto.curve.createPoint(new BigInteger("42"), new BigInteger("1337"));
    UsageProofOfExponent pokNotOnCurve = new UsageProofOfExponent(point, pok.getChallengeResponse());
    assertFalse(pokNotOnCurve.validateParameters());
    assertFalse(AttestationCrypto.verifyEqualityProof(com1, com2, pokNotOnCurve));
  }

}
