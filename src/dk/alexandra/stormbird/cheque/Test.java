package dk.alexandra.stormbird.cheque;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Random;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;

public class Test {
  private static final String RECEIVER_ADDRESS = "0x666666666666";
  private static final String RECEIVER_IDENTITY = "tore@alex.dk";
  private static final int RECEIVER_TYPE = 0; // 0: email, 1:phone

  private static final String SENDER_ADDRESS = "0x424242424242";
  private static final int SENDER_AMOUNT = 42;

  @org.junit.Test
  public void testHidingOfPoint() throws Exception {
    SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
    rnd.setSeed("seed".getBytes());
    Crypto crypto = new Crypto(rnd);
    String identity = "tore@alex.dk";
    int type = 0;
    BigInteger riddleSolution = crypto.makeRandomExponent();
    ECPoint riddle = crypto.generateRiddle(type, identity, riddleSolution);

    BigInteger secret = crypto.makeRandomExponent();
    ECPoint identifier = crypto.generateRiddle(type, identity, secret);
    BigInteger x = secret.modInverse(crypto.curveOrder).multiply(riddleSolution).mod(crypto.curveOrder);
    // It now holds that identifier.multiply(x) = riddle
    ECPoint expectedRiddle = identifier.multiply(x);
    Assert.assertEquals(expectedRiddle.getX().toBigInteger(), (riddle.getX().toBigInteger()));
  }

  @org.junit.Test
  public void testProof() throws Exception {
    SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
    rnd.setSeed("seed".getBytes());
    Crypto crypto = new Crypto(rnd);
    ECPoint base = crypto.spec.getG();
    BigInteger exponent = crypto.makeRandomExponent();
    ECPoint challenge = base.multiply(exponent);
    List<byte[]> proof = crypto.computeProof(base, challenge, exponent);
    Assert.assertTrue(crypto.verifyProof(proof));
  }

  @org.junit.Test
  public void sunshine() throws Exception {
    // Deterministic for testing purposes ONLY!!
    SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
    rnd.setSeed("seed".getBytes());
    Crypto crypto = new Crypto(rnd);

    // SENDER
    KeyPair senderKeys = crypto.createKeyPair();
    Sender s = new Sender(SENDER_ADDRESS, senderKeys, crypto);
    ChequeAndSecret chequeAndSec = s.makeCheque(RECEIVER_IDENTITY, RECEIVER_TYPE, SENDER_AMOUNT);

    // RECEIVER
    KeyPair receiverKeys = crypto.createKeyPair();
    Receiver r = new Receiver(RECEIVER_ADDRESS, receiverKeys, crypto);
    CSRAndSecret csrAndSec = r.createCSR(RECEIVER_IDENTITY, RECEIVER_TYPE);

    // CA
    CA ca = new CA(crypto.createKeyPair());
    X509Certificate cert = ca.makeCert(csrAndSec.getCsr());

    // RECEIVER
    Proof proof = r.redeemCheque(chequeAndSec, cert, csrAndSec.getSecret());

    // SMART CONTRACT
    SmartContract sm = new SmartContract(crypto);
    Assert.assertTrue(sm.cashCheque(cert, proof, chequeAndSec.getCheque()));
  }

}
