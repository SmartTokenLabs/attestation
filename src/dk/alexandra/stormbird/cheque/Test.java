package dk.alexandra.stormbird.cheque;

import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import com.objsys.asn1j.runtime.Asn1DerDecodeBuffer;
import dk.alexandra.stormbird.cheque.asnobjects.MyAttestation;
import dk.alexandra.stormbird.cheque.asnobjects.RedeemCheque;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.junit.Assert;
import sun.security.x509.X509CertImpl;

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
    KeyPair caKeys = crypto.createKeyPair();
    CA ca = new CA(caKeys);
    X509Certificate cert = ca.makeCert(csrAndSec.getCsr());

    // RECEIVER
    RedeemCheque redeem = r.redeemCheque(chequeAndSec, cert, csrAndSec.getSecret(), receiverKeys);

    // SMART CONTRACT
    SmartContractDummy sm = new SmartContractDummy(crypto);
    Assert.assertTrue(sm.cashCheque(redeem, caKeys.getPublic(), senderKeys.getPublic()));
  }

  @org.junit.Test
  // Ensure that the ASN1 specification we have for the attestation is compatible with X509v3
  public void testAttestationX509Compatibility() throws Exception {
    Crypto crypto = new Crypto(new SecureRandom("seed".getBytes()));
    KeyPair keys = crypto.createKeyPair();
    X509V3CertificateGenerator serverCertGen = new X509V3CertificateGenerator();
    serverCertGen.setSerialNumber(new BigInteger("123456789"));
    // X509Certificate caCert=null;
    serverCertGen.setIssuerDN(new X509Name("CN=Alex"));
    serverCertGen.setNotBefore(new Date());
    serverCertGen.setNotAfter(new Date(System.currentTimeMillis() + 2592000000L));
    serverCertGen.setSubjectDN(new X509Name("CN=Homer-Simpson"));
    serverCertGen.setPublicKey(keys.getPublic());
    serverCertGen.setSignatureAlgorithm("SHA256withECDSA");
    // CRITICAL is always set to true
    serverCertGen.addExtension(new DERObjectIdentifier(Util.OID_OCTETSTRING), true,  new DEROctetString("something".getBytes()));

    // We have created a cert that should also be an attestation for cheque
    X509Certificate cert = serverCertGen.generateX509Certificate(keys.getPrivate(), "BC");

    // Now try to convert it to an attestation object
    MyAttestation attestation = new MyAttestation();
    Asn1BerDecodeBuffer buffer = new Asn1DerDecodeBuffer(cert.getEncoded());
    attestation.decode (buffer);

    // Try to convert it back to a certificate
    InputStream inStream = new ByteArrayInputStream(Util.encodeASNObject(attestation));
    X509Certificate cert2 = new X509CertImpl(inStream);

    Assert.assertTrue(cert.equals(cert2));
  }

}
