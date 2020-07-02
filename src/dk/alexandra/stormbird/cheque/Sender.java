package dk.alexandra.stormbird.cheque;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.util.Random;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.Fp;
import org.bouncycastle.math.ec.ECPoint;

public class Sender {
  private static final int COMP_SEC = 32; // 256 bits
  private final String address;
  private final Random rand;

  public Sender(String address) {
    this.address = address;
    rand = new SecureRandom(); // This MUST not be deterministic. Java self-seeds SecureRandom
  }

  public byte[] makeSecret() {
    return new BigInteger(256, rand).toByteArray();
  }

  public Cheque makeCheque(String identifier, int type, int amount, byte[] secret) {
    ECPoint riddle = generateRiddle(type, identifier, new BigInteger(secret));
    return new Cheque(amount, riddle.getEncoded());
  }

  private ECPoint generateRiddle(int type, String identifier, BigInteger secret) {
    try {
      BigInteger idenNum = mapToInteger(type, identifier.getBytes(StandardCharsets.UTF_8));

      ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
      ECNamedCurveSpec params = new ECNamedCurveSpec("secp256k1", spec.getCurve(), spec.getG(),
          spec.getN());
      BigInteger fieldSize = ((ECFieldFp)params.getCurve().getField()).getP();

      ECPoint identityGen = computePoint(spec.getCurve(), fieldSize, idenNum);
      return identityGen.multiply(secret);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private BigInteger mapToInteger(int type, byte[] identity) {
    try {
      // We use HMAC to avoid issues with extension attacks, although SHA3 or doubble hashing should be sufficient on its own
      Mac mac = Mac.getInstance("HmacSHA256");
      SecretKeySpec keySpec = new SecretKeySpec("static_key".getBytes((StandardCharsets.UTF_8)), "HmacSHA256");
      mac.init(keySpec);
      mac.update(ByteBuffer.allocate(4).putInt(type).array());
      mac.update(identity);
      byte[] macData = mac.doFinal();

      BigInteger idenNum = new BigInteger(macData);
      idenNum.abs();
      return idenNum;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Compute a specific point on the curve (generator) based on x
   * @param params
   * @param p The size of the underlying field
   * @param x The x-coordiante for which we will compute y
   * @return A corresponding y coordinate for x
   */
  public ECPoint computePoint(ECCurve params, BigInteger p, BigInteger x) {
    x = x.mod(p);
    BigInteger y, expected, ySquare;
    do {
      x = x.add(BigInteger.ONE).mod(p);
      BigInteger a = params.getA().toBigInteger();
      BigInteger b = params.getB().toBigInteger();
      ySquare = x.modPow(new BigInteger("3"), p).add(a.multiply(x)).add(b).mod(p);
      // Since we use secp256k1 we use the Lagrange trick to compute the squareroot (since p mod 4=3)
      BigInteger magicExp = p.add(BigInteger.ONE).divide(new BigInteger("4"));
      y = ySquare.modPow(magicExp, p);
      // Check that the squareroot actually exists and hence that we have a point on the curve
      expected = y.multiply(y).mod(p);
    } while (!expected.equals(ySquare));
    return params.createPoint(x, y, false);
  }
}
