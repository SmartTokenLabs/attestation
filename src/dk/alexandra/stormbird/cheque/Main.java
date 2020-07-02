package dk.alexandra.stormbird.cheque;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;

public class Main {

  public static void main(String args[]) {
    String identifier = "lol";
    int type = 0;
    Sender s = new Sender("0x424242");
    byte[] secret = s.makeSecret();
    Cheque cheque = s.makeCheque(identifier,type, 42, secret);

    try {
      Receiver r = new Receiver("0x66666666");
      KeyPair keys = r.createKeyPair();
      byte[] csr = r.createCSR(keys, secret, identifier,type);
      byte[] decoded = Base64.getEncoder().encode(csr);
      System.out.println(new String(decoded));
      r.receiveCheque(cheque);
    } catch (Exception e ) {
      e.printStackTrace();
    }
  }
}
