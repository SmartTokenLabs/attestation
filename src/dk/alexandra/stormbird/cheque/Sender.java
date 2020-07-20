package dk.alexandra.stormbird.cheque;

import com.objsys.asn1j.runtime.Asn1BitString;
import dk.alexandra.stormbird.cheque.asnobjects.Cheque;
import dk.alexandra.stormbird.cheque.asnobjects.SignedCheque;
import java.math.BigInteger;
import java.security.KeyPair;
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
