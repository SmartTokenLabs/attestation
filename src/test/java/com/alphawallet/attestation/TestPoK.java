package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.demo.SmartContract;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.apache.logging.log4j.core.util.Assert;
import org.junit.jupiter.api.Test;

public class TestPoK {

  @Test
  public void TestSunshine() {
    AttestationCrypto crypto = new AttestationCrypto(new SecureRandom());
    ProofOfExponent pok = crypto.constructProof("hello", AttestationType.PHONE, BigInteger.TEN);
    assertTrue(pok.verify());
    SmartContract sc = new SmartContract();
    sc.testEncoding(pok);
    ProofOfExponent newPok = new ProofOfExponent(pok.getDerEncoding());
    assertTrue(newPok.verify());
    assertEquals(pok.getBase(), newPok.getBase());
    assertEquals(pok.getRiddle(), newPok.getRiddle());
    assertEquals(pok.getPoint(), newPok.getPoint());
    assertEquals(pok.getChallenge(), newPok.getChallenge());
    assertArrayEquals(pok.getDerEncoding(), newPok.getDerEncoding());

    ProofOfExponent newConstructor = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint(), pok.getChallenge());
    assertArrayEquals(pok.getDerEncoding(), newConstructor.getDerEncoding());
  }

  @Test
  public void TestNegative() {
    AttestationCrypto crypto = new AttestationCrypto(new SecureRandom());
    ProofOfExponent pok = crypto.constructProof("hello", AttestationType.PHONE, BigInteger.TEN);
    assertTrue(pok.verify());
    ProofOfExponent newPok;
    newPok = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
    assertFalse(newPok.verify());
    newPok = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint().multiply(new BigInteger("2")), pok.getChallenge());
    assertFalse(newPok.verify());
    newPok = new ProofOfExponent(pok.getBase().multiply(new BigInteger("2")), pok.getRiddle(), pok.getPoint(), pok.getChallenge());
    assertFalse(newPok.verify());
    newPok = new ProofOfExponent(pok.getBase(), pok.getRiddle().multiply(new BigInteger("2")), pok.getPoint(), pok.getChallenge());
    assertFalse(newPok.verify());
  }

  @Test
  public void TestContract()
  {
    AttestationCrypto crypto = new AttestationCrypto(new SecureRandom());

    SecureRandom rand = new SecureRandom();
    SmartContract sc = new SmartContract();

    for (int i = 0; i < 30; i++)
    {
      byte[] bytes = new byte[32];
      rand.nextBytes(bytes);
      BigInteger rVal = new BigInteger(bytes);
      ProofOfExponent pok = crypto.constructProof("hello", AttestationType.PHONE, rVal);
      assertTrue(pok.verify());
      assertTrue(sc.testEncoding(pok));
    }

    //now check fail
    for (int i = 0; i < 5; i++)
    {
      byte[] bytes = new byte[32];
      rand.nextBytes(bytes);
      BigInteger rVal = new BigInteger(bytes);
      ProofOfExponent pok = crypto.constructProof("hello", AttestationType.PHONE, rVal);
      assertTrue(pok.verify());
      ProofOfExponent newPok = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
      assertFalse(sc.testEncoding(newPok));
    }
  }

}
