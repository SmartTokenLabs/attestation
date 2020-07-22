package dk.alexandra.stormbird.cheque;

import com.objsys.asn1j.runtime.Asn1BitString;
import com.objsys.asn1j.runtime.Asn1GeneralizedTime;
import dk.alexandra.stormbird.cheque.asnobjects.Cheque;
import dk.alexandra.stormbird.cheque.asnobjects.SignedCheque;
import dk.alexandra.stormbird.cheque.asnobjects.Time;
import dk.alexandra.stormbird.cheque.asnobjects.ValidityValue;
import java.math.BigInteger;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
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
    DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
    LocalDateTime currentTime = LocalDateTime.now();
    Time now = new Time();
    now.set_generalizedTime(new Asn1GeneralizedTime(currentTime.format(dtf)));
    Time later = new Time();
    // Cheque is valid from now and the next 30 days
    LocalDateTime laterTime = currentTime.plusDays(30);
    later.set_generalizedTime(new Asn1GeneralizedTime(laterTime.format(dtf)));
    ValidityValue validity = new ValidityValue(now, later);
    Cheque unsignedCheque = new Cheque(amount, validity, riddle.getEncoded());
    byte[] unsignedChequeBytes = Util.encodeASNObject(unsignedCheque);
    byte[] signature = crypto.signBytes(unsignedChequeBytes, keys);
    SignedCheque signedCheque = new SignedCheque(unsignedCheque, new Asn1BitString(keys.getPublic().getEncoded()), new Asn1BitString(signature));
    return  new ChequeAndSecret(signedCheque, secret);
  }
}
