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

  private final String address;

  public Sender(String address) {
    this.address = address;
  }

  public Cheque makeCheque(String identifier, int type, int amount, BigInteger secret) {
//    ECPoint riddle = Crypto.generateRiddle(type, identifier, secret);
//    return new Cheque(amount, riddle.getEncoded());
    return null;
  }
}
