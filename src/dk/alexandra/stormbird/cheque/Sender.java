package dk.alexandra.stormbird.cheque;

import com.objsys.asn1j.runtime.Asn1BitString;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
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
  private final KeyPair keys;
  private final Crypto crypto;

  public Sender(String address, KeyPair keys, Crypto crypto) {
    this.crypto = crypto;
    this.address = address;
    this.keys = keys;
  }

  public ChequeAndSecret makeCheque(String identifier, int type, int amount) throws Exception {
    BigInteger secret = crypto.makeRandomExponent();
    ECPoint riddle = crypto.generateRiddle(type, identifier, secret);
    Cheque unsignedCheque = new Cheque(amount, riddle.getEncoded());
    byte[] unsignedChequeBytes = Util.encodeASNObject(unsignedCheque);
    byte[] signature = crypto.signBytes(unsignedChequeBytes, keys);
    SignedCheque signedCheque = new SignedCheque(unsignedCheque, new Asn1BitString(keys.getPublic().getEncoded()), new Asn1BitString(signature));
    return  new ChequeAndSecret(signedCheque, secret);
  }
}
