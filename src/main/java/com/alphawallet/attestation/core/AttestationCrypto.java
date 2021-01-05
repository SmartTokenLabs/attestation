package com.alphawallet.attestation.core;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.ProofOfExponent;
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
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class AttestationCrypto {
  public static final String ECDSA_CURVE = "secp256k1";
  public static final String MAC_ALGO = "HmacSHA256";
  public static final String OID_SIGNATURE_ALG = "1.2.840.10045.2.1"; // OID for elliptic curve crypto
  public static final X9ECParameters ECDSACurve = SECNamedCurves.getByName(AttestationCrypto.ECDSA_CURVE);
  public static final ECDomainParameters ECDSAdomain = new ECDomainParameters(ECDSACurve.getCurve(), ECDSACurve.getG(), ECDSACurve.getN(), ECDSACurve.getH());
  public static final BigInteger fieldSize = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
  // IMPORTANT: if another group is used then curveOrder should be the largest subgroup order
  public static final BigInteger curveOrder = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
  // NOTE: Curve order for BN256 is 254 bit
  public static final int curveOrderBitLength = curveOrder.bitLength(); // minus 1 since the bitcount includes an extra bit for sign since BigInteger is two's complement
  public static final BigInteger cofactor = new BigInteger("1");
  public static final ECCurve curve = new Fp(fieldSize, BigInteger.ZERO, new BigInteger("3"), curveOrder, cofactor);
  // Generator for message part of Pedersen commitments generated deterministically from mapToInteger queried on 0 and mapped to the curve using try-and-increment
  public static final ECPoint G = curve.createPoint(new BigInteger("15729599519504045482191519010597390184315499143087863467258091083496429125073"), new BigInteger("1368880882406055711853124887741765079727455879193744504977106900552137574951"));
  // Generator for randomness part of Pedersen commitments generated deterministically from  mapToInteger queried on 1 to the curve using try-and-increment
  public static final ECPoint H = curve.createPoint(new BigInteger("10071451177251346351593122552258400731070307792115572537969044314339076126231"), new BigInteger("2894161621123416739138844080004799398680035544501805450971689609134516348045"));
  private final SecureRandom rand;

  public AttestationCrypto(SecureRandom rand) {
    Security.addProvider(new BouncyCastleProvider());
    this.rand = rand;
    if (!verifyCurveOrder(curveOrder)) {
      throw new RuntimeException("Static values do not work with current implementation");
    }
  }

  private boolean verifyCurveOrder(BigInteger curveOrder) {
    // Verify that the curve order is less than 2^256 bits, which is required by mapToCurveMultiplier
    // Specifically checking if it is larger than 2^curveOrderBitLength and that no bits at position curveOrderBitLength+1 or larger are set
    if (curveOrder.compareTo(BigInteger.ONE.shiftLeft(curveOrderBitLength-1)) < 0 || curveOrder.shiftRight(curveOrderBitLength).compareTo(BigInteger.ZERO) > 0) {
      System.err.println("Curve order is not 254 bits which is required by the current implementation");
      return false;
    }
    return true;
  }

  /**
   * Code shamelessly stolen from https://medium.com/@fixone/ecc-for-ethereum-on-android-7e35dc6624c9
   * @param key
   * @return
   */
  public static String addressFromKey(AsymmetricKeyParameter key) {
    // Todo should be verified that is works as intended, are there any reference values?
    byte[] pubKey;
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);
      pubKey = spki.getPublicKeyData().getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    //discard the first byte which only tells what kind of key it is //i.e. encoded/un-encoded
    pubKey = Arrays.copyOfRange(pubKey,1,pubKey.length);
    MessageDigest KECCAK = new Keccak.Digest256();
    KECCAK.reset();
    KECCAK.update(pubKey);
    byte[] hash = KECCAK.digest();
    //finally get only the last 20 bytes
    return "0x" + Hex.toHexString(Arrays.copyOfRange(hash,hash.length-20,hash.length)).toUpperCase();
  }

  public AsymmetricCipherKeyPair constructECKeys() {
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(ECDSAdomain, rand);
    generator.init(keygenParams);
    return generator.generateKeyPair();
  }


  /**
   * Construct a Pedersen commitment to an identifier using a specific secret.
   * @param identity The common identifier
   * @param type The type of identifier
   * @param secret The secret randomness to be used in the commitment
   * @return
   */
  public static byte[] makeCommitment(String identity, AttestationType type, BigInteger secret) {
    BigInteger hashedIdentity = mapToCurveMultiplier(type, identity);
    // Construct Pedersen commitment
    ECPoint commitment = G.multiply(hashedIdentity).add(H.multiply(secret));
    return commitment.getEncoded(false);
  }

  /**
   * Constructs a commitment to an identity based on hidden randomization supplied from a user.
   * This is used to construct an attestation.
   * @param identity The user's identity.
   * @param type The type of identity.
   * @param hiding The hiding the user has picked
   * @return
   */
  public static byte[] makeCommitment(String identity, AttestationType type, ECPoint hiding) {
    BigInteger hashedIdentity = mapToCurveMultiplier(type, identity);
    // Construct Pedersen commitment
    ECPoint commitment = G.multiply(hashedIdentity).add(hiding);
    return commitment.getEncoded(false);
  }

  /**
   * Computes a proof of knowledge of a random exponent
   * This is used to convince the attestor that the user knows a secret which the attestor will
   * then use to construct a Pedersen commitment to the user's identifier.
   * @param randomness The randomness used in the commitment
   * @return
   */
  public ProofOfExponent computeAttestationProof(BigInteger randomness) {
    // Compute the random part of the commitment, i.e. H^randomness
    ECPoint riddle = H.multiply(randomness);
    List<ECPoint> challengeList = Arrays.asList(H, riddle);
    return constructSchnorrPOK(riddle, randomness, challengeList);
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
   * @return
   */
  public ProofOfExponent computeEqualityProof(byte[] commitment1, byte[] commitment2, BigInteger randomness1, BigInteger randomness2) {
    ECPoint comPoint1 = decodePoint(commitment1);
    ECPoint comPoint2 = decodePoint(commitment2);
    // Compute H*(randomness1-randomness2=commitment1-commitment2=G*msg+H*randomness1-G*msg+H*randomness2
    ECPoint riddle = comPoint1.subtract(comPoint2);
    BigInteger exponent = randomness1.subtract(randomness2).mod(curveOrder);
    List<ECPoint> challengeList = Arrays.asList(H, comPoint1, comPoint2);
    return constructSchnorrPOK(riddle, exponent, challengeList);
  }

  /**
   * Constructs a Schnorr proof of knowledge of exponent of a riddle to base H.
   * The challenge value used (c) is computed from the challengeList and the internal t value.
   * The method uses rejection sampling to ensure that the t value is sampled s.t. the
   * challenge will always be less than curveOrder.
   */
  private ProofOfExponent constructSchnorrPOK(ECPoint riddle, BigInteger exponent, List<ECPoint> challengeList) {
    ECPoint t;
    BigInteger c, d;
    // Use rejection sampling to sample a hiding value s.t. the random oracle challenge c computed from it is less than curveOrder
    do {
      BigInteger hiding = makeSecret();
      t = H.multiply(hiding);
      List<ECPoint> finalChallengeList = new ArrayList<>(challengeList);
      finalChallengeList.add(t);
      c = mapTo256BitInteger(makeArray(finalChallengeList));
      d = hiding.add(c.multiply(exponent)).mod(curveOrder);
    } while (c.compareTo(curveOrder) >= 0);
    return new ProofOfExponent(H, riddle.normalize(), t.normalize(), d);
  }

  /**
   * Verifies a zero knowledge proof of knowledge of a riddle used in an attestation request
   * @param pok The proof to verify
   * @return True if the proof is OK and false otherwise
   */
  public static boolean verifyAttestationRequestProof(ProofOfExponent pok)  {
    BigInteger c = mapTo256BitInteger(makeArray(Arrays.asList(pok.getBase(), pok.getRiddle(), pok.getPoint())));
    // Ensure that the right base has been used in the proof
    if (!pok.getBase().equals(H)) {
      return false;
    }
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
    ECPoint comPoint1 = decodePoint(commitment1);
    ECPoint comPoint2 = decodePoint(commitment2);
    // Compute the value the riddle should have
    ECPoint riddle = comPoint1.subtract(comPoint2);
    // Verify the proof matches the commitments
    if (!riddle.equals(pok.getRiddle())) {
      return false;
    }
    // Ensure that the right base has been used in the proof
    if (!pok.getBase().equals(H)) {
      return false;
    }
    BigInteger c = mapTo256BitInteger(makeArray(Arrays.asList(pok.getBase(), comPoint1, comPoint2, pok.getPoint())));
    return verifyPok(pok, c);
  }

  private static boolean verifyPok(ProofOfExponent pok, BigInteger c) {
    ECPoint lhs = pok.getBase().multiply(pok.getChallenge());
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
      throw new RuntimeException(e);
    }
  }

  /**
   * Map a byte array into a uniformly random 256 bit (positive) integer, stored as a Big Integer.
   */
  static BigInteger mapTo256BitInteger(byte[] input) {
    try {
      MessageDigest KECCAK = new Keccak.Digest256();
      KECCAK.reset();
      // In case of failure we rehash using the old output
      KECCAK.update(input);
      byte[] digest = KECCAK.digest();
      // Construct an positive BigInteger from the bytes
      return new BigInteger(1, digest);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Maps and identifier of a certain type to an integer deterministic, yet sampled from
   * the uniformly random distribution between 0 and curveOrder -1.
   * This is done using deterministic rejection sampling based on the input.
   */
  public static BigInteger mapToCurveMultiplier(AttestationType type, String identity) {
    byte[] identityBytes = identity.trim().toLowerCase().getBytes(StandardCharsets.UTF_8);
    ByteBuffer buf = ByteBuffer.allocate(4 + identityBytes.length);
    buf.putInt(type.ordinal());
    buf.put(identityBytes);
    BigInteger sampledVal = new BigInteger(1, buf.array());
    do {
      sampledVal = mapTo256BitInteger(sampledVal.toByteArray());
    } while (sampledVal.compareTo(curveOrder) >= 0);
    return sampledVal;
  }

  public static ECPoint decodePoint(byte[] point) {
    return curve.decodePoint(point).normalize();
  }
}
