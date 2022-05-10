package org.tokenscript.attestation.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECPoint;
import org.tokenscript.attestation.FullProofOfExponent;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.ProofOfExponent;
import org.tokenscript.attestation.UsageProofOfExponent;

public class AttestationCrypto {
  private static final Logger logger = LogManager.getLogger(AttestationCrypto.class);

  public static final int BYTES_IN_DIGEST = 256 / 8;
  public static final BigInteger fieldSize = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
  // IMPORTANT: If another group is used then curveOrder should be the largest subgroup order and it should be ensured that G and H lie on this subgroup!
  public static final BigInteger curveOrder = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
  // NOTE: Curve order for BN256 is 254 bit
  // Security is equivalent to about 100 bits, it has been decided to be "good enough" for this application since other curves would be significantly more expensive to use on Ethereum
  // See https://eips.ethereum.org/EIPS/eip-3068 for details
  public static final int curveOrderBitLength = 254; // minus 1 since the bitcount includes an extra bit for sign since BigInteger is two's complement
  // IMPORTANT: This should be updated and taken into account when sampling generators if the group is changed
  public static final BigInteger cofactor = new BigInteger("1");
  public static final ECCurve curve = new Fp(fieldSize, BigInteger.ZERO, new BigInteger("3"), curveOrder, cofactor);
  // Generator for message part of Pedersen commitments generated deterministically from mapToInteger queried on 0 and mapped to the curve using try-and-increment
  public static final ECPoint G = curve.createPoint(new BigInteger("21282764439311451829394129092047993080259557426320933158672611067687630484067"), new BigInteger("3813889942691430704369624600187664845713336792511424430006907067499686345744"));
  // Generator for randomness part of Pedersen commitments generated deterministically from  mapToInteger queried on 1 to the curve using try-and-increment
  public static final ECPoint H = curve.createPoint(new BigInteger("10844896013696871595893151490650636250667003995871483372134187278207473369077"), new BigInteger("9393217696329481319187854592386054938412168121447413803797200472841959383227"));
  private final SecureRandom rand;

  public AttestationCrypto(SecureRandom rand) {
    Security.addProvider(new BouncyCastleProvider());
    this.rand = rand;
    if (!verifyCurveOrder()) {
      throw new RuntimeException("Static values do not work with current implementation");
    }
  }

  private boolean verifyCurveOrder() {
    // Sanity check static values
    AttestationCrypto.validatePointToCurve(G, curve);
    AttestationCrypto.validatePointToCurve(H, curve);
    // Verify that the curve order is less than 2^256 bits, which is required by mapToCurveMultiplier
    // Specifically checking if it is larger than 2^curveOrderBitLength and that no bits at position curveOrderBitLength+1 or larger are set
    if (curve.getOrder().compareTo(BigInteger.ONE.shiftLeft(curveOrderBitLength-1)) < 0 || curve.getOrder().shiftRight(curveOrderBitLength).compareTo(BigInteger.ZERO) > 0) {
      logger.error("Curve order is not 254 bits which is required by the current implementation");
      return false;
    }
    return true;
  }

  public static byte[] hashWithKeccak(byte[] toHash) {
    MessageDigest KECCAK = new Keccak.Digest256();
    KECCAK.reset();
    KECCAK.update(toHash);
    return KECCAK.digest();
  }

  public static byte[] hashWithSHA256(byte[] toHash) {
    MessageDigest sha256 = new SHA256.Digest();
    sha256.reset();
    sha256.update(toHash);
    return sha256.digest();
  }

  /**
   * Construct a Pedersen commitment to an identifier using a specific secret.
   * @param identifier The common identifier
   * @param type The type of identifier
   * @param secret The secret randomness to be used in the commitment
   * @return
   */
  public static byte[] makeCommitment(String identifier, AttestationType type, BigInteger secret) {
    BigInteger hashedIdentifier = mapToCurveMultiplier(type, identifier);
    // Construct Pedersen commitment
    ECPoint commitment = G.multiply(hashedIdentifier).add(H.multiply(secret));
    return commitment.getEncoded(false);
  }

  /**
   * Constructs a commitment to an identifier based on hidden randomization supplied from a user.
   * This is used to construct an attestation.
   * @param identifier The user's identifier.
   * @param type The type of identifier.
   * @param hiding The hiding the user has picked
   * @return
   */
  public static byte[] makeCommitment(String identifier, AttestationType type, ECPoint hiding) {
    // Check for malicious input
    AttestationCrypto.validatePointToCurve(hiding, curve);
    BigInteger hashedIdentifier = mapToCurveMultiplier(type, identifier);
    // Construct Pedersen commitment
    ECPoint commitment = G.multiply(hashedIdentifier).add(hiding);
    return commitment.getEncoded(false);
  }

  /**
   * Computes a proof of knowledge of a random exponent
   * This is used to convince the attestor that the user knows a secret which the attestor will
   * then use to construct a Pedersen commitment to the user's identifier.
   * @param randomness The randomness used in the commitment
   * @param unpredictableNumber A unpredictableNumber to link the proof to a specific context/challenge
   * @return
   */
  public FullProofOfExponent computeAttestationProof(BigInteger randomness, byte[] unpredictableNumber) {
    // Compute the random part of the commitment, i.e. H^randomness
    ECPoint riddle = H.multiply(randomness);
    List<ECPoint> challengeList = Arrays.asList(H, riddle);
    return constructSchnorrPOK(riddle, randomness, challengeList, unpredictableNumber);
  }

  public FullProofOfExponent computeAttestationProof(BigInteger randomness) {
    return computeAttestationProof(randomness, new byte[0]);
  }

  /**
   * Compute a proof that commitment1 and commitment2 are Pedersen commitments to the same message and that the user
   * knows randomness1-randomness2.
   * NOTE: We are actually not proving that the user knows the message and randomness1 and randomness2.
   * This is because we assume the user has already proven knowledge of his message (mail) and the
   * randomness1 used in the attestation to the attestor. Because of this assumption it is enough to prove
   * knowledge of randomness2 (equivalent to proving knowledge of randomness1-randomness2) and that the
   * commitments are to the same message.
   * The reason we do this is that this weaker proof is significantly cheaper to execute on the blockchain.
   *
   * In conclusion what this method actually proves is knowledge that randomness1-randomness2 is the
   * discrete log of commitment1/commitment2.
   * I.e. that commitment1/commitment2 =H^(randomness1-randomness2)
   * @param commitment1 First Pedersen commitment to some message m
   * @param commitment2 Second Pedersen commitment to some message m
   * @param randomness1 The randomness used in commitment1
   * @param randomness2 The randomness used in commitment2
   * @param unpredictableNumber A unpredictable number to link the proof to a specific context/challenge
   * @return
   */
  public UsageProofOfExponent computeEqualityProof(byte[] commitment1, byte[] commitment2, BigInteger randomness1, BigInteger randomness2, byte[] unpredictableNumber) {
    ECPoint comPoint1 = decodePoint(commitment1);
    ECPoint comPoint2 = decodePoint(commitment2);
    // Compute H*(randomness1-randomness2=commitment1-commitment2=G*msg+H*randomness1-G*msg+H*randomness2
    ECPoint riddle = comPoint1.subtract(comPoint2);
    BigInteger exponent = randomness1.subtract(randomness2).mod(curveOrder);
    List<ECPoint> challengeList = Arrays.asList(H, comPoint1, comPoint2);
    return constructSchnorrPOK(riddle, exponent, challengeList, unpredictableNumber).getUsageProofOfExponent();
  }

  public UsageProofOfExponent computeEqualityProof(byte[] commitment1, byte[] commitment2, BigInteger randomness1, BigInteger randomness2) {
    return computeEqualityProof(commitment1, commitment2, randomness1, randomness2, new byte[0]);
  }

  /**
   * Constructs a Schnorr proof of knowledge of exponent of a riddle to base H.
   * The challenge value used (c) is computed from the challengePoints and the internal t value.
   * The method uses rejection sampling to ensure that the t value is sampled s.t. the
   * challenge will always be less than curveOrder.
   */
  private FullProofOfExponent constructSchnorrPOK(ECPoint riddle, BigInteger exponent, List<ECPoint> challengePoints, byte[] unpredictableNumber) {
    ECPoint t;
    BigInteger hiding, c, d;
    // Use rejection sampling to sample a hiding value s.t. the random oracle challenge c computed from it is less than curveOrder.
    // This is needed to prevent bias in the randomness. Even small bias can causes issues for some curves, see for example https://eprint.iacr.org/2020/615.pdf
    do {
      hiding = makeSecret();
      t = H.multiply(hiding);
      c = computeChallenge(t, challengePoints, unpredictableNumber);
    } while (c.compareTo(curveOrder) >= 0);
    d = hiding.add(c.multiply(exponent)).mod(curveOrder);
    return new FullProofOfExponent(riddle.normalize(), t.normalize(), d, unpredictableNumber);
  }

  private static BigInteger computeChallenge(ECPoint t, List<ECPoint> challengeList, byte[] unpredictableNumber) {
    List<ECPoint> finalChallengeList = new ArrayList<>(challengeList);
    finalChallengeList.add(t);
    byte[] challengePointBytes = makeArray(finalChallengeList);
    byte[] challengeBytes = new byte[challengePointBytes.length+unpredictableNumber.length];
    System.arraycopy(challengePointBytes, 0, challengeBytes, 0, challengePointBytes.length);
    System.arraycopy(unpredictableNumber, 0, challengeBytes, challengePointBytes.length, unpredictableNumber.length);
    return mapToInteger(challengeBytes);
  }

  /**
   * Verifies a zero knowledge proof of knowledge of a riddle used in an attestation request
   * @param pok The proof to verify
   * @return True if the proof is OK and false otherwise
   */
  public static boolean verifyFullProof(FullProofOfExponent pok)  {
    if (!pok.validateParameters()) {
      logger.error("The parameters in the ZK proof are not correct");
      return false;
    }
    BigInteger c = computeChallenge(pok.getPoint(), Arrays.asList(H, pok.getRiddle()), pok.getUnpredictableNumber());
    return verifyPok(pok, c);
  }

  /**
   * Verifies a zero knowledge proof of knowledge of the two riddles used in two different
   * commitments to the same message.
   * This is used by the smart contract to verify that a request is ok where one commitment is the
   * riddle for a cheque/ticket and the other is the riddle from an attesation.
   * @param pok The proof to verify
   * @return True if the proof is OK and false otherwise
   */
  public static boolean verifyEqualityProof(byte[] commitment1, byte[] commitment2, ProofOfExponent pok)  {
    if (!pok.validateParameters()) {
      logger.error("The parameters in the ZK proof are not correct");
      return false;
    }
    ECPoint comPoint1 = decodePoint(commitment1);
    ECPoint comPoint2 = decodePoint(commitment2);
    // Compute the value the riddle should have
    ECPoint riddle = comPoint1.subtract(comPoint2);
    BigInteger c = computeChallenge(pok.getPoint(), Arrays.asList(H, comPoint1, comPoint2), pok.getUnpredictableNumber());
    return verifyPok(new FullProofOfExponent(riddle, pok.getPoint(), pok.getChallengeResponse(), pok.getUnpredictableNumber()), c);
  }

  private static boolean verifyPok(FullProofOfExponent pok, BigInteger c) {
    // Check that the c has been sampled correctly using rejection sampling
    if (c.compareTo(curveOrder) >= 0 || c.compareTo(BigInteger.ZERO) <= 0) {
      logger.error("Challenge is not of the correct size");
      return false;
    }
    ECPoint lhs = H.multiply(pok.getChallengeResponse());
    ECPoint rhs = pok.getRiddle().multiply(c).add(pok.getPoint());
    return lhs.equals(rhs);
  }

  public BigInteger makeSecret() {
    return new BigInteger(256+128, rand).mod(curveOrder);
  }

  static byte[] makeArray(List<ECPoint> points ) {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      for (ECPoint current : points) {
        outputStream.write(current.normalize().getEncoded(false));
      }
      byte[] res = outputStream.toByteArray();
      outputStream.close();
      return res;
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode EC points", e);
    }
  }

  /**
   * Map a byte array into a uniformly random curveOrderBitLength bit (positive) integer, stored as a Big Integer.
   */
  static BigInteger mapToInteger(byte[] input) {
    try {
      byte[] digest = hashWithKeccak(input);
      // Construct a non-negative BigInteger from the bytes
      BigInteger resultOf256Bits =  new BigInteger(1, digest);
      return resultOf256Bits.shiftRight(256-curveOrderBitLength);
    } catch (Exception e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not map to integer", e);
    }
  }

  /**
   * Maps and identifier of a certain type to an integer deterministic, yet sampled from
   * the uniformly random distribution between 0 and curveOrder -1.
   * This is done using deterministic rejection sampling based on the input.
   */
  public static BigInteger mapToCurveMultiplier(AttestationType type, String identifier) {
    byte[] identifierBytes = identifier.trim().toLowerCase().getBytes(StandardCharsets.UTF_8);
    ByteBuffer buf = ByteBuffer.allocate(4 + identifierBytes.length);
    buf.putInt(type.ordinal());
    buf.put(identifierBytes);
    BigInteger sampledVal = new BigInteger(1, buf.array());
    do {
      sampledVal = mapToInteger(sampledVal.toByteArray());
    } while (sampledVal.compareTo(curveOrder) >= 0);
    return sampledVal;
  }

  public static ECPoint decodePoint(byte[] point) {
    ECPoint ecPoint = curve.decodePoint(point).normalize();
    // Check for malicious input
    AttestationCrypto.validatePointToCurve(ecPoint, curve);
    // Check there is no subgroup attack, since we specifically use a curve with cofactor 1
    if (!cofactor.equals(BigInteger.ONE)) {
      ExceptionUtil.throwException(logger, new InternalError("We have only implemented checks for curves with cofactor 1"));
    }
    return ecPoint;
  }

  /**
   * Performs standard security checks that the point is on the curve, has the correct order and is not the point at infinity.
   * If the point is not considered safe, then a SecurityException is thrown.
   */
  public static void validatePointToCurve(ECPoint point, ECCurve curve) throws SecurityException {
    try {
      if (point.isInfinity()) {
        throw new SecurityException("Point is at infinity");
      }
      ECPoint normalizedPoint = point.normalize();
      // Ensure the point is on the curve
      curve.validatePoint(normalizedPoint.getAffineXCoord().toBigInteger(), normalizedPoint.getAffineYCoord().toBigInteger());
      if (!point.multiply(curve.getOrder()).isInfinity()) {
        throw new SecurityException("Point does not have correct order");
      }
    } catch (Exception e) {
      ExceptionUtil.throwException(logger, new SecurityException(e.getMessage()));
    }
  }
}
