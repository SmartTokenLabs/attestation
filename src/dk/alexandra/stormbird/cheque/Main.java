package dk.alexandra.stormbird.cheque;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.math.ec.ECPoint;
import com.objsys.asn1j.runtime.*;

public class Main {
  private static final String RECEIVER_ADDRESS = "0x666666666666";
  private static final String RECEIVER_IDENTITY = "tore@alex.dk";
  private static final int RECEIVER_TYPE = 0; // 0: email, 1:phone

  private static final String SENDER_ADDRESS = "0x424242424242";
  private static final int SENDER_AMOUNT = 42;


  public static void main(String args[])  {
    try {
      // Deterministic for testing purposes ONLY!!
      SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
      rnd.setSeed("seed".getBytes());
      Crypto crypto = new Crypto(rnd);

      // SENDER
      KeyPair senderKeys = crypto.createKeyPair();
      Sender s = new Sender(SENDER_ADDRESS, senderKeys, crypto);
      ChequeAndSecret chequeAndSec = s.makeCheque(RECEIVER_IDENTITY, RECEIVER_TYPE, SENDER_AMOUNT);
      System.out.println(Util.printCheque(chequeAndSec.getCheque()));

      // RECEIVER
      KeyPair receiverKeys = crypto.createKeyPair();
      Receiver r = new Receiver(RECEIVER_ADDRESS, receiverKeys, crypto);
      CSRAndSecret csrAndSec = r.createCSR(RECEIVER_IDENTITY, RECEIVER_TYPE);
      System.out.println(Util.printDERCSR(csrAndSec.getCsr()));

      // CA
      CA ca = new CA(crypto.createKeyPair());
      X509Certificate cert = ca.makeCert(csrAndSec.getCsr());
      System.out.println(Util.printDERCert(cert));

      // RECEIVER
      Proof proof = r.redeemCheque(chequeAndSec, cert, csrAndSec.getSecret());

      // SMART CONTRACT
      SmartContract sm = new SmartContract(crypto);
      // TODO this should be an ASN1 RedeemCheque (signed) object instead, but I have not been able to parse x509v3 to Java
      if (!sm.cashCheque(cert, proof, chequeAndSec.getCheque())) {
        System.out.println("Failed to accept cashing request");
      }
    } catch (Exception e ) {
      e.printStackTrace();
    }
  }
}
