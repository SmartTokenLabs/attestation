package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.demo.SmartContract;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import com.alphawallet.token.tools.Numeric;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class ProofOfKnowledgeTest {

  public static final BigInteger SECRET1 = new BigInteger("5848910840846872525745834000448648789786746461");
  public static final BigInteger SECRET2 = new BigInteger("640848948534656666878789789789484891065000");
  public static final String ID = "test@test.ts";

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
    assertTrue(crypto.verifyAttestationRequestProof(pok));
    SmartContract sc = new SmartContract();
    sc.testEncoding(pok);
    FullProofOfExponent newPok = new FullProofOfExponent(pok.getDerEncoding());
    assertTrue(crypto.verifyAttestationRequestProof(newPok));
    assertEquals(pok.getRiddle(), newPok.getRiddle());
    assertEquals(pok.getPoint(), newPok.getPoint());
    assertEquals(pok.getChallenge(), newPok.getChallenge());
    assertArrayEquals(pok.getDerEncoding(), newPok.getDerEncoding());

    FullProofOfExponent newConstructor = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallenge());
    assertArrayEquals(pok.getDerEncoding(), newConstructor.getDerEncoding());
  }

  @Test
  public void TestNegativeAttestationProof() {
    FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.TEN);
    assertTrue(crypto.verifyAttestationRequestProof(pok));
    FullProofOfExponent newPok;
    newPok = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
    assertFalse(crypto.verifyAttestationRequestProof(newPok));
    newPok = new FullProofOfExponent(pok.getRiddle(), pok.getPoint().multiply(new BigInteger("2")), pok.getChallenge());
    assertFalse(crypto.verifyAttestationRequestProof(newPok));
    newPok = new FullProofOfExponent(pok.getRiddle().multiply(new BigInteger("2")), pok.getPoint(), pok.getChallenge());
    assertFalse(crypto.verifyAttestationRequestProof(newPok));
  }

  @Test
  public void TestSunshineEqualityProof() throws Exception {
    byte[] com1 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET1);
    byte[] com2 = crypto.makeCommitment(ID, AttestationType.EMAIL, SECRET2);
    ProofOfExponent pok = crypto.computeEqualityProof(com1, com2, SECRET1, SECRET2);
    assertTrue(crypto.verifyEqualityProof(com1, com2, pok));
    SmartContract sc = new SmartContract();
    sc.verifyEqualityProof(com1, com2, pok);
    UsageProofOfExponent newPok = new UsageProofOfExponent(pok.getDerEncoding());
    assertTrue(crypto.verifyEqualityProof(com1, com2, newPok));
    assertEquals(pok.getPoint(), newPok.getPoint());
    assertEquals(pok.getChallenge(), newPok.getChallenge());
    assertArrayEquals(pok.getDerEncoding(), newPok.getDerEncoding());

    ProofOfExponent newConstructor = new UsageProofOfExponent(pok.getPoint(), pok.getChallenge());
    assertArrayEquals(pok.getDerEncoding(), newConstructor.getDerEncoding());
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

  @Test
  public void TestContract() throws Exception {
    gen.setSeed(12345678L); //fixed for testing purposes
    SmartContract sc = new SmartContract();

    BigInteger localSecret1 = new BigInteger("5848910840846872525745834000448648789786746461");
    BigInteger localSecret2 = new BigInteger("640848948534656666878789789789484891065000");

    // Equality proof soak test
    for (int i = 0; i < 1000; i++)
    {
      String id = generateID();
      localSecret1 = localSecret1.add(BigInteger.ONE);
      localSecret2 = localSecret2.add(BigInteger.ONE);
      byte[] com1 = crypto.makeCommitment(id, AttestationType.EMAIL, localSecret1);
      byte[] com2 = crypto.makeCommitment(id, AttestationType.EMAIL, localSecret2);
      ProofOfExponent pok = crypto.computeEqualityProof(com1, com2, localSecret1, localSecret2);
      System.out.println("com1: " + Numeric.toHexString(com1));
      System.out.println("com2: " + Numeric.toHexString(com2));
      System.out.println(Numeric.toHexString(pok.getDerEncoding()));
      assertTrue(crypto.verifyEqualityProof(com1, com2, pok));
      assertTrue(sc.verifyEqualityProof(com1, com2, pok));
    }

    // Negative tests
    for (int i = 0; i < 100; i++)
    {
      String id = generateID();
      localSecret1 = localSecret1.add(BigInteger.ONE);
      localSecret2 = localSecret2.add(BigInteger.ONE);
      byte[] com1 = crypto.makeCommitment(id, AttestationType.EMAIL, localSecret1);
      byte[] com2 = crypto.makeCommitment(id, AttestationType.EMAIL, localSecret2);
      ProofOfExponent pok = crypto.computeEqualityProof(com1, com2, localSecret1, localSecret2);
      UsageProofOfExponent newPok = new UsageProofOfExponent(pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
      boolean negativeCheck = sc.verifyEqualityProof(com1, com2, newPok);
      System.out.println("-> " + (negativeCheck ? "Contract call should fail! Check Failed" : "Negative check Passed"));
      assertFalse(negativeCheck);
    }

    // FullProofOfExponent attestation request proof
    for (int i = 0; i < 10; i++)
    {
      FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.TEN.add(BigInteger.valueOf(i)));
      assertTrue(crypto.verifyAttestationRequestProof(pok));
      assertTrue(sc.testEncoding(pok));
    }

    // FullProofOfExponent negative test
    for (int i = 0; i < 5; i++)
    {
      FullProofOfExponent pok = crypto.computeAttestationProof(BigInteger.TEN.add(BigInteger.valueOf(i)));
      assertTrue(crypto.verifyAttestationRequestProof(pok));
      FullProofOfExponent newPok = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
      boolean negativeCheck = sc.testEncoding(newPok);
      System.out.println("-> " + (negativeCheck ? "Contract call should fail! Check Failed" : "Negative check Passed"));
      assertFalse(negativeCheck);
    }
  }

  private final static Random gen = new Random();

  //Generates a fairly random email address
  private String generateID()
  {
    return names[gen.nextInt(names.length)].toLowerCase() + "@" +
            names[gen.nextInt(names.length)].toLowerCase() +
            suffixes[gen.nextInt(suffixes.length)];
  }

  static final String[] names = { "Violet",
          "Marcelline",
          "Darlleen",
          "Adelle",
          "Di",
          "Merrie",
          "Asia",
          "Lesly",
          "Fredericka",
          "Anestassia",
          "Brana",
          "Cathie",
          "Joelly",
          "Christian",
          "Elvira",
          "Joelly",
          "Lita",
          "Mahalia",
          "Judy",
          "Marcelline",
          "Belva",
          "Dione",
          "Max",
          "Justin",
          "Roxanne",
          "Tom",
          "Dick",
          "Harry" };

  static final String[] suffixes = { ".com",
          ".co.uk",
          ".org",
          ".io",
          ".com.au",
          ".edu",
          ".co",
          ".cn",
          ".jp",
          ".xyz",
          ".eth" };
}
