package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TestCrypto {
  private AsymmetricCipherKeyPair subjectKeys;
  private AsymmetricCipherKeyPair issuerKeys;
  private AsymmetricCipherKeyPair senderKeys;
  private SecureRandom rand;
  private AttestationCrypto crypto;
  private static final String ID = "test@test.ts";
  private static final AttestationType TYPE = AttestationType.EMAIL;
  private static final BigInteger SECRET = new BigInteger("684084084843542003217847860141382018669978641584584765489");

  @BeforeEach
  public void setupCrypto() throws NoSuchAlgorithmException {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    crypto = new AttestationCrypto(rand);
    subjectKeys = crypto.constructECKeys();
    issuerKeys = crypto.constructECKeys();
    senderKeys = crypto.constructECKeys();
  }

  @Test
  public void testAddressFromKey() {
    String key = AttestationCrypto.addressFromKey(subjectKeys.getPublic());
    assertTrue(key.startsWith("0x"));
    assertEquals(key.length(), 2+2*20); // prefix 0x and two chars per byte
    // Assert consistency
    String keyAgain = AttestationCrypto.addressFromKey(subjectKeys.getPublic());
    assertTrue(keyAgain.equals(key));

    // Negative test
    String otherKey = AttestationCrypto.addressFromKey(issuerKeys.getPublic());
    assertFalse(otherKey.equals(key));
  }

  @Test
  public void testMakeRiddle() {
    byte[] point = AttestationCrypto.makeRiddle(ID, TYPE, SECRET);
    // Sanity checks
    assertTrue(point.length > 32);
    assertFalse(Arrays.equals(point, new byte[point.length]));

    // Check consistency
    byte[] point2 = AttestationCrypto.makeRiddle(ID, TYPE, SECRET);
    assertArrayEquals(point, point2);

    // Negative tests
    point2 = AttestationCrypto.makeRiddle("test", TYPE, SECRET);
    assertFalse(Arrays.equals(point, point2));
    point2 = AttestationCrypto.makeRiddle(ID + "   1", TYPE, SECRET);
    assertFalse(Arrays.equals(point, point2));
    point2 = AttestationCrypto.makeRiddle(ID, AttestationType.PHONE, SECRET);
    assertFalse(Arrays.equals(point, point2));
    point2 = AttestationCrypto.makeRiddle(ID, TYPE, SECRET.add(BigInteger.ONE));
    assertFalse(Arrays.equals(point, point2));
  }

  @Test
  public void testVerifyProof() {
    ProofOfExponent pok = crypto.constructProof(ID, TYPE, SECRET);
    assertTrue(AttestationCrypto.verifyProof(pok));
    // Test with other randomness
    ProofOfExponent pok2 = crypto.constructProof(ID, TYPE, SECRET);
    assertTrue(AttestationCrypto.verifyProof(pok2));
    assertNotEquals(pok.getPoint(), pok2.getPoint());
    assertNotEquals(pok.getChallenge(), pok2.getChallenge());
    assertEquals(pok.getBase(), pok2.getBase());
    assertEquals(pok.getRiddle(), pok2.getRiddle());

    // Test with other type
    pok = crypto.constructProof(ID, AttestationType.PHONE, SECRET);
    assertTrue(AttestationCrypto.verifyProof(pok));

    // Test with other secret
    pok = crypto.constructProof(ID, AttestationType.PHONE, BigInteger.ONE);
    assertTrue(AttestationCrypto.verifyProof(pok));

    // Negative tests
    pok = crypto.constructProof(ID, TYPE, SECRET);
    pok2 = new ProofOfExponent(pok.getBase().add(pok.getBase()), pok.getRiddle(), pok.getPoint(), pok.getChallenge());
    assertFalse(AttestationCrypto.verifyProof(pok2));

    pok2 = new ProofOfExponent(pok.getBase(), pok.getRiddle().add(pok.getBase()), pok.getPoint(), pok.getChallenge());
    assertFalse(AttestationCrypto.verifyProof(pok2));

    pok2 = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint().add(pok.getBase()), pok.getChallenge());
    assertFalse(AttestationCrypto.verifyProof(pok2));

    pok2 = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
    assertFalse(AttestationCrypto.verifyProof(pok2));
  }

  @Test
  public void testMakeSecret() {
    BigInteger sec = crypto.makeSecret();
    // Sanity check
    assertTrue(sec.bitLength() > 230); // Except with negligible prob the minimal representation will be at least 230 bits
    // Check not static
    BigInteger sec2 = crypto.makeSecret();
    assertNotEquals(sec, sec2);
  }

  @Test
  public void testHashIdentifier() {
    ECPoint point = AttestationCrypto.hashIdentifier(TYPE.ordinal(), ID);
    // Sanity checks
    assertFalse(point.isInfinity());

    // Check consistency
    ECPoint point2 = AttestationCrypto.hashIdentifier(TYPE.ordinal(), ID);
    assertEquals(point, point2);

    // Sanity check algorithms
    for (int i = 0; i < 20; i++) {
      point = AttestationCrypto.hashIdentifier(i % 2 , String.valueOf(i));
      ECCurve curve = AttestationCrypto.curve;
      // Verify that y^2 = x^3 + ax + b
      BigInteger ySquared = point.getYCoord().multiply(point.getYCoord()).toBigInteger();
      BigInteger x = point.getXCoord().toBigInteger();
      // expected = x^3+Ax+B
      BigInteger expected = x.multiply(x).multiply(x).add(
          x.multiply(curve.getA().toBigInteger())).add(
              curve.getB().toBigInteger()).mod(AttestationCrypto.fieldSize);
      assertEquals(ySquared, expected);

      // Verify the order is correct
      ECPoint o = point.multiply(AttestationCrypto.curveOrder.subtract(BigInteger.ONE)).normalize();
      assertFalse(o.isInfinity());
      assertFalse(point.isInfinity());
      assertEquals(o.getXCoord(), point.getXCoord());
      // Sanity check
      o = point.multiply(AttestationCrypto.curveOrder).normalize();
      assertNotEquals(o.getXCoord(), point.getXCoord());
      o = point.multiply(AttestationCrypto.fieldSize).normalize();
      assertNotEquals(o.getXCoord(), point.getXCoord());
      assertFalse(o.isInfinity());
    }
    // Negative tests
    point2 = AttestationCrypto.hashIdentifier(TYPE.ordinal(), "test");
    assertNotEquals(point.getXCoord(), point2.getXCoord());
    point2 = AttestationCrypto.hashIdentifier(TYPE.ordinal(), ID + "   1");
    assertNotEquals(point.getXCoord(), point2.getXCoord());
    point2 = AttestationCrypto.hashIdentifier(AttestationType.PHONE.ordinal(), ID);
    assertNotEquals(point.getXCoord(), point2.getXCoord());
  }

  @Test
  public void testConstructProof() throws NoSuchAlgorithmException{
    SecureRandom rand2 = SecureRandom.getInstance("SHA1PRNG");
    rand2.setSeed("otherseed".getBytes());
    AttestationCrypto crypt2 = new AttestationCrypto(rand2);
    ProofOfExponent pok = crypt2.constructProof(ID, TYPE, SECRET);
    assertTrue(pok.verify());

    // Check consistency
    rand2 = SecureRandom.getInstance("SHA1PRNG");
    rand2.setSeed("otherseed".getBytes());
    crypt2 = new AttestationCrypto(rand2);
    ProofOfExponent pok2 = crypt2.constructProof(ID, TYPE, SECRET);
    assertEquals(pok.getBase(), pok2.getBase());
    assertEquals(pok.getPoint(), pok2.getPoint());
    assertEquals(pok.getRiddle(), pok2.getRiddle());
    assertEquals(pok.getChallenge(), pok2.getChallenge());
  }

  @Test
  public void testDecodePoint() {
    ECPoint point = AttestationCrypto.hashIdentifier(TYPE.ordinal(), ID);
    byte[] encoded = point.getEncoded(false);
    ECPoint decoded = AttestationCrypto.decodePoint(encoded);
    assertEquals(point, decoded);

    ECPoint newPoint = point.add(point);
    byte[] newEncoded = newPoint.getEncoded(false);
    ECPoint newDecoded = AttestationCrypto.decodePoint(newEncoded);
    assertEquals(newPoint, newDecoded);

    // Negative tests
    assertNotEquals(point, newPoint);
    assertNotEquals(encoded, newEncoded);
    assertNotEquals(decoded, newDecoded);
  }
}
