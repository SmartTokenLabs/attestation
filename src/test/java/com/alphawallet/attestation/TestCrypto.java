package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
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
  public void testMakeCommitment() {
    byte[] point = AttestationCrypto.makeCommitment(ID, TYPE, SECRET);
    // Sanity checks
    assertTrue(point.length > 32);
    assertFalse(Arrays.equals(point, new byte[point.length]));
    ECPoint encodedPoint = AttestationCrypto.decodePoint(point);
    assertFalse(encodedPoint.isInfinity());

    // Check consistency
    byte[] point2 = AttestationCrypto.makeCommitment(ID, TYPE, SECRET);
    assertArrayEquals(point, point2);

    // Negative tests
    point2 = AttestationCrypto.makeCommitment("test", TYPE, SECRET);
    assertFalse(Arrays.equals(point, point2));
    point2 = AttestationCrypto.makeCommitment(ID + "   1", TYPE, SECRET);
    assertFalse(Arrays.equals(point, point2));
    point2 = AttestationCrypto.makeCommitment(ID, AttestationType.PHONE, SECRET);
    assertFalse(Arrays.equals(point, point2));
    point2 = AttestationCrypto.makeCommitment(ID, TYPE, SECRET.add(BigInteger.ONE));
    assertFalse(Arrays.equals(point, point2));
  }

  @Test
  public void testMakeRiddle() {
    ECPoint hiding = AttestationCrypto.H.multiply(SECRET);
    byte[] riddleBytes = AttestationCrypto.makeRiddle(ID, TYPE, hiding);
    byte[] commitmentBytes = AttestationCrypto.makeCommitment(ID, TYPE, SECRET);
    ECPoint riddle = AttestationCrypto.decodePoint(riddleBytes);
    // Sanity checks
    assertFalse(riddle.isInfinity());
    assertArrayEquals(riddleBytes, commitmentBytes);

    // Check consistency
    byte[] riddleBytes2 = AttestationCrypto.makeCommitment(ID, TYPE, SECRET);
    assertArrayEquals(riddleBytes, riddleBytes2);

    // Negative tests
    riddleBytes2 = AttestationCrypto.makeRiddle("test", TYPE, hiding);
    assertFalse(Arrays.equals(riddleBytes, riddleBytes2));
    riddleBytes2 = AttestationCrypto.makeRiddle(ID + "   1", TYPE, hiding);
    assertFalse(Arrays.equals(riddleBytes, riddleBytes2));
    riddleBytes2 = AttestationCrypto.makeRiddle(ID, AttestationType.PHONE, hiding);
    assertFalse(Arrays.equals(riddleBytes, riddleBytes2));
    riddleBytes2 = AttestationCrypto.makeRiddle(ID, TYPE, hiding.add(hiding));
    assertFalse(Arrays.equals(riddleBytes, riddleBytes2));
  }

  @Test
  public void testVerifyAttestationRequestProof() {
    ProofOfExponent pok = crypto.computeAttestationProof(SECRET);
    assertTrue(AttestationCrypto.verifyAttestationRequestProof(pok));
    // Test with other randomness
    ProofOfExponent pok2 = crypto.computeAttestationProof(SECRET);
    assertTrue(AttestationCrypto.verifyAttestationRequestProof(pok2));
    assertNotEquals(pok.getPoint(), pok2.getPoint());
    assertNotEquals(pok.getChallenge(), pok2.getChallenge());
    assertEquals(pok.getBase(), pok2.getBase());
    assertEquals(pok.getRiddle(), pok2.getRiddle());

    // Test with other type
    pok = crypto.computeAttestationProof(SECRET);
    assertTrue(AttestationCrypto.verifyAttestationRequestProof(pok));

    // Test with other secret
    pok = crypto.computeAttestationProof(BigInteger.ONE);
    assertTrue(AttestationCrypto.verifyAttestationRequestProof(pok));

    // Negative tests
    pok = crypto.computeAttestationProof(SECRET);
    pok2 = new ProofOfExponent(pok.getBase().add(pok.getBase()), pok.getRiddle(), pok.getPoint(), pok.getChallenge());
    assertFalse(AttestationCrypto.verifyAttestationRequestProof(pok2));

    pok2 = new ProofOfExponent(pok.getBase(), pok.getRiddle().add(pok.getBase()), pok.getPoint(), pok.getChallenge());
    assertFalse(AttestationCrypto.verifyAttestationRequestProof(pok2));

    pok2 = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint().add(pok.getBase()), pok.getChallenge());
    assertFalse(AttestationCrypto.verifyAttestationRequestProof(pok2));

    pok2 = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
    assertFalse(AttestationCrypto.verifyAttestationRequestProof(pok2));
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
  public void testMapToInteger() {
    BigInteger value = AttestationCrypto.mapToInteger(TYPE.ordinal(), ID);
    // Sanity checks
    assertFalse(value.equals(BigInteger.ZERO));
    assertFalse(value.equals(BigInteger.ONE));
    assertFalse(value.equals(AttestationCrypto.curveOrder));
    assertFalse(value.equals(AttestationCrypto.fieldSize));
    assertFalse(value.equals(AttestationCrypto.curveOrder.subtract(BigInteger.ONE)));
    assertFalse(value.equals(AttestationCrypto.fieldSize.subtract(BigInteger.ONE)));
    assertTrue(value.compareTo(AttestationCrypto.curveOrder) < 0 );

    // Check consistency
    BigInteger value2 = AttestationCrypto.mapToInteger(TYPE.ordinal(), ID);
    assertEquals(value, value2);

    // Negative tests
    value2 = AttestationCrypto.mapToInteger(TYPE.ordinal(), "test");
    assertNotEquals(value, value2);
    value2 = AttestationCrypto.mapToInteger(TYPE.ordinal(), ID + "   1");
    assertNotEquals(value, value2);
    value2 = AttestationCrypto.mapToInteger(AttestationType.PHONE.ordinal(), ID);
    assertNotEquals(value, value2);
  }

  @Test
  public void testConstructAttRequestProof() throws NoSuchAlgorithmException{
    SecureRandom rand2 = SecureRandom.getInstance("SHA1PRNG");
    rand2.setSeed("otherseed".getBytes());
    AttestationCrypto crypt2 = new AttestationCrypto(rand2);
    ProofOfExponent pok = crypt2.computeAttestationProof(SECRET);
    assertTrue(AttestationCrypto.verifyAttestationRequestProof(pok));

    // Check consistency
    rand2 = SecureRandom.getInstance("SHA1PRNG");
    rand2.setSeed("otherseed".getBytes());
    crypt2 = new AttestationCrypto(rand2);
    ProofOfExponent pok2 = crypt2.computeAttestationProof(SECRET);
    assertEquals(pok.getBase(), pok2.getBase());
    assertEquals(pok.getPoint(), pok2.getPoint());
    assertEquals(pok.getRiddle(), pok2.getRiddle());
    assertEquals(pok.getChallenge(), pok2.getChallenge());
  }

  @Test
  public void testDecodePoint() {
    byte[] encoded = AttestationCrypto.makeCommitment(ID, TYPE, SECRET);
    ECPoint decoded = AttestationCrypto.decodePoint(encoded);
    ECPoint point = AttestationCrypto.curve.decodePoint(encoded);
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

  @Test
  public void computeGenerators() throws Exception {
    Method mapToInteger = AttestationCrypto.class.getDeclaredMethod("mapToInteger", byte[].class);
    mapToInteger.setAccessible(true);
    Method computePoint = AttestationCrypto.class.getDeclaredMethod("computePoint", BigInteger.class);
    computePoint.setAccessible(true);

    byte[] input = new byte[1];
    input[0] = 0;
    BigInteger gVal = (BigInteger) mapToInteger.invoke(crypto, input);
    ECPoint g = (ECPoint) computePoint.invoke(crypto, gVal);
    assertEquals(AttestationCrypto.G, g);
    input[0] = 1;
    BigInteger hVal = (BigInteger) mapToInteger.invoke(crypto, input);
    ECPoint h = (ECPoint) computePoint.invoke(crypto, hVal);
    assertEquals(AttestationCrypto.H, h);
  }
}
