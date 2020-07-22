package dk.alexandra.stormbird.cheque;

import dk.alexandra.stormbird.cheque.asnobjects.RedeemCheque;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

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
      RedeemCheque redeem = r.redeemCheque(chequeAndSec, cert, csrAndSec.getSecret(), receiverKeys);
      System.out.println(Util.printRedeem(redeem));

      // SMART CONTRACT
      SmartContractDummy sm = new SmartContractDummy(crypto);
      if (!sm.cashCheque(redeem)) {
        System.out.println("Failed to accept cashing request");
      }
    } catch (Exception e ) {
      e.printStackTrace();
    }
  }
}
