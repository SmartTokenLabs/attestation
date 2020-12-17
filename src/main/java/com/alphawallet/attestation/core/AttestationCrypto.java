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
  public static final BigInteger fieldSize = new BigInteger("115792089237314936872688561244471742058375878355761205198700409522629664518163");
  // IMPORTANT: if another group is used then curveOrder should be the largest subgroup order
  public static final BigInteger curveOrder = new BigInteger("115792089237314936872688561244471742058035595988840268584488757999429535617037");
  public static final ECCurve curve = new Fp(fieldSize, BigInteger.ZERO, new BigInteger("3"), curveOrder, BigInteger.ONE);
  private final SecureRandom rand;

  public AttestationCrypto(SecureRandom rand) {
    Security.addProvider(new BouncyCastleProvider());
    this.rand = rand;
    // Verify that fieldSize = 3 mod 4, otherwise the crypto won't work
    if (!fieldSize.mod(new BigInteger("4")).equals(new BigInteger("3"))) {
      throw new RuntimeException("The crypto will not work with this choice of curve");
    }
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
   * Constructs a riddle based on a secret and returns a proof of knowledge of this
   */
  public ProofOfExponent constructProof(String identity, AttestationType type, BigInteger secret) {
    ECPoint hashedIdentity = hashIdentifier(type.ordinal(), identity);
    ECPoint identifier = hashedIdentity.multiply(secret);
    return computeProof(hashedIdentity, identifier, secret);
  }

  public static byte[] makeRiddle(String identity, AttestationType type, BigInteger secret) {
    ECPoint hashedIdentity = hashIdentifier(type.ordinal(), identity);
    ECPoint res = hashedIdentity.multiply(secret).normalize();
    return res.getEncoded(false);
  }

  public ProofOfExponent computeProof(ECPoint base, ECPoint riddle, BigInteger exponent) {
    BigInteger r = makeSecret();
    ECPoint t = base.multiply(r);
    // TODO ideally Bob's ethreum address should also be part of the challenge
    BigInteger c = mapToInteger(makeArray(Arrays.asList(base, riddle, t))).mod(curveOrder);
    BigInteger d = r.add(c.multiply(exponent)).mod(curveOrder);
    return new ProofOfExponent(base, riddle, t, d);
  }

  public static boolean verifyProof(ProofOfExponent pok)  {
    BigInteger c = mapToInteger(makeArray(Arrays.asList(pok.getBase(), pok.getRiddle(), pok.getPoint()))).mod(curveOrder);
    ECPoint lhs = pok.getBase().multiply(pok.getChallenge());
    ECPoint rhs = pok.getRiddle().multiply(c).add(pok.getPoint());
    return lhs.equals(rhs);
  }

  public BigInteger makeSecret() {
    return new BigInteger(256+128, rand).mod(curveOrder);
  }

  private static byte[] makeArray(List<ECPoint> points ) {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      for (ECPoint current : points) {
        outputStream.write(current.getEncoded(false));
      }
      byte[] res = outputStream.toByteArray();
      outputStream.close();
      return res;
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

   public static ECPoint hashIdentifier(int type, String identifier) {
    // TODO check that identifier is legal in other ways
    BigInteger idenNum = mapToInteger(type, identifier.trim().toLowerCase().getBytes(StandardCharsets.UTF_8));
    return computePoint(idenNum);
  }

  private static BigInteger mapToInteger(byte[] value) {
    try {
      final MessageDigest digest = MessageDigest.getInstance("Keccak-384");
      BigInteger idenNum = new BigInteger( digest.digest(value));
      return idenNum.mod(fieldSize);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static BigInteger mapToInteger(int type, byte[] identity) {
    ByteBuffer buf = ByteBuffer.allocate(4 + identity.length);
    buf.putInt(type);
    buf.put(identity);
    return mapToInteger(buf.array());
  }

  /**
   * Compute a specific point on the curve (generator) based on x using the try-and-increment method
   * https://eprint.iacr.org/2009/226.pdf
   * @param x The x-coordinate for which we will compute y
   * @return A corresponding y coordinate for x
   */
  private static ECPoint computePoint(BigInteger x) {
    x = x.mod(fieldSize);
    BigInteger ySquare, quadraticResidue;
    ECPoint resPoint, referencePoint;
    do {
      do {
        x = x.add(BigInteger.ONE).mod(fieldSize);
        BigInteger a = curve.getA().toBigInteger();
        BigInteger b = curve.getB().toBigInteger();
        ySquare = x.modPow(new BigInteger("3"), fieldSize).add(a.multiply(x)).add(b).mod(fieldSize);
        BigInteger quadraticResidueExp = fieldSize.subtract(BigInteger.ONE).shiftRight(1);
        quadraticResidue = ySquare.modPow(quadraticResidueExp, fieldSize);
      } while (!quadraticResidue.equals(BigInteger.ONE));
      // We use the Lagrange trick to compute the squareroot (since fieldSize mod 4=3)
      BigInteger magicExp = fieldSize.add(BigInteger.ONE).shiftRight(2); // fieldSize + 1 / 4
      BigInteger y = ySquare.modPow(magicExp, fieldSize);
      resPoint = curve.createPoint(x, y).normalize();
      // Ensure that we have a consistent choice of which "sign" of y we use. We always use the smallest possible value of y
      if (resPoint.getYCoord().toBigInteger().compareTo(fieldSize.shiftRight(1)) > 0) {
        resPoint = resPoint.negate().normalize();
      }
      referencePoint = resPoint.multiply(curveOrder.subtract(BigInteger.ONE)).normalize();
      if (referencePoint.getYCoord().toBigInteger().compareTo(fieldSize.shiftRight(1)) > 0) {
        referencePoint = referencePoint.negate().normalize();
      }
      // Verify that the element is a member of the expected (subgroup) by ensuring that it has the right order, through Fermat's little theorem
      // NOTE: this is ONLY needed if we DON'T use secp256k1, so currently it is superflous but we are keeping it this check is crucial for security on most other curves!
    } while(!resPoint.equals(referencePoint) || resPoint.isInfinity());
    return resPoint.normalize();
  }

  public static ECPoint decodePoint(byte[] point) {
    return curve.decodePoint(point).normalize();
  }
}
