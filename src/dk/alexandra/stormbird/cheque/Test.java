package dk.alexandra.stormbird.cheque;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Random;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;

public class Test {

  @org.junit.Test
  public void testHidingOfPoint() throws Exception{
    Crypto crypto = new Crypto(new Random(42));
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
    Crypto crypto = new Crypto(new Random(42));
    ECPoint base = crypto.spec.getG();
    BigInteger exponent = crypto.makeRandomExponent();
    ECPoint challenge = base.multiply(exponent);
    List<byte[]> proof = crypto.computeProof(base, challenge, exponent);
    Assert.assertTrue(crypto.verifyProof(proof));
  }

  @org.junit.Test
  public void testCertDecoding() throws Exception {
    Receiver r = new Receiver("0x123456");
    Crypto crypto = new Crypto(new Random(42));
    KeyPair keys = crypto.createKeyPair();
    PKCS10CertificationRequest csr = r.createCSR(keys, crypto.spec.getG());
    System.out.println(Util.printDERCSR(csr));
    CA ca = new CA("0x33333333", crypto.createKeyPair());
    X509Certificate cert = ca.makeCert(csr);
    byte[] byteIdentifier = cert.getExtensionValue("1.3.6.1.4.1.1466.115.121.1.40");
    ASN1InputStream input = new ASN1InputStream(byteIdentifier);
    DEROctetString object = (DEROctetString) input.readObject();
    // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
    input = new ASN1InputStream(object.getOctets());
    object = (DEROctetString) input.readObject();
    ECPoint decodedIdentifier = crypto.decodePoint(object.getOctets());
    Assert.assertEquals(crypto.spec.getG(), decodedIdentifier);
  }
}
