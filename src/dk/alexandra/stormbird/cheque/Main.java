package dk.alexandra.stormbird.cheque;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.math.ec.ECPoint;

public class Main {

  public static void main(String args[])  {
    try {
      Crypto crypto = new Crypto(new SecureRandom());
      String identity = "tore@alex.dk";
      int type = 0;
      Sender s = new Sender("0x424242");
      BigInteger riddleSolution = crypto.makeRandomExponent();
      ECPoint riddle = crypto.generateRiddle(type, identity, riddleSolution);
      KeyPair senderKeys = crypto.createKeyPair();
      Cheque cheque = new Cheque(42, riddle.getEncoded());

      Receiver r = new Receiver("0x66666666");
      KeyPair keys = crypto.createKeyPair();
      BigInteger secret = crypto.makeRandomExponent();
      ECPoint identifier = crypto.generateRiddle(type, identity, secret);
      PKCS10CertificationRequest csr = r.createCSR(keys, identifier);
      System.out.println(Util.printDERCSR(csr));
      CA ca = new CA("0x33333333", crypto.createKeyPair());
      X509Certificate cert = ca.makeCert(csr);
      System.out.println(Util.printDERCert(cert));

      ECPoint decodedRiddle = crypto.decodePoint(cheque.getRiddle());
      BigInteger x = secret.modInverse(crypto.curveOrder).multiply(riddleSolution).mod(crypto.curveOrder);
      // It now holds that identifier.multiply(x) = riddle
      List<byte[]> proof = crypto.computeProof(identifier, decodedRiddle, x);

      cert.checkValidity();
      cert.verify(cert.getPublicKey(), "BC");
      // Retrieve string
      byte[] byteIdentifier = cert.getExtensionValue("1.3.6.1.4.1.1466.115.121.1.40");
      ASN1InputStream input = new ASN1InputStream(byteIdentifier);
      DEROctetString object = (DEROctetString) input.readObject();
      // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
      input = new ASN1InputStream(object.getOctets());
      object = (DEROctetString) input.readObject();
      ECPoint decodedIdentifier = crypto.decodePoint(object.getOctets());
      if (!Arrays.equals(decodedIdentifier.getEncoded(), proof.get(0))) {
        throw new RuntimeException("Identity of proof and cert does not match");
      }
      if (!crypto.verifyProof(proof)) {
        throw new RuntimeException("Proof did not verify");
      }

    } catch (Exception e ) {
      e.printStackTrace();
    }
  }
}
