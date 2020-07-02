package dk.alexandra.stormbird.cheque;

import com.sun.jarsigner.ContentSigner;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;
import sun.security.pkcs10.PKCS10;
import sun.security.x509.X500Name;

public class Receiver {
  private final SecureRandom rand;
  private final String address;
  private static final X9ECParameters curve = SECNamedCurves.getByName ("secp256k1");
  private static final ECDomainParameters domain = new ECDomainParameters (curve.getCurve (), curve.getG (), curve.getN (), curve.getH ());

  public Receiver(String address) {
    this.address = address;
    rand = new SecureRandom(); // This MUST not be deterministic. Java self-seeds SecureRandom
  }

  public KeyPair createKeyPair() throws Exception {

    Security.addProvider(new BouncyCastleProvider());
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
    keyGen.initialize(ecSpec, new SecureRandom());
    return keyGen.generateKeyPair();
  }

  public AsymmetricCipherKeyPair createBCKeys() throws Exception {
        X9ECParameters curve = SECNamedCurves.getByName ("secp256k1");
    ECDomainParameters domain = new ECDomainParameters (curve.getCurve (), curve.getG (), curve.getN (), curve.getH ());
    ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters (domain, rand);
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    generator.init (keygenParams);
    AsymmetricCipherKeyPair keypair = generator.generateKeyPair ();
    ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate ();
    ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic ();
    return  keypair;
  }

  /**
   * DER encoded CSR with ECDSA SHA256 spec
   * @param keys
   * @param secret
   * @param identifier
   * @param type
   * @return
   * @throws Exception
   */
  public byte[] createCSR(KeyPair keys, byte[] secret, String identifier, int type) throws Exception {
    X509Principal name = new X509Principal("CN=" + address);
    ASN1Set attributes = new DERSet(
        new DERSequence(new ASN1Encodable[] {
          new DEROctetString(secret), new DERInteger(type)
    }));

    // OID for ECDSA with SHA256
    PKCS10CertificationRequest csr = new PKCS10CertificationRequest("1.2.840.10045.4.3.2", name, keys.getPublic(), attributes, keys.getPrivate());
    return csr.getDEREncoded();

// generate PKCS10 certificate request
//    String sigAlg = "ECDSA";
//    PKCS10 pkcs10 = new PKCS10(keys.getPublic());
//    Signature signature = Signature.getInstance(sigAlg);
//    signature.initSign(keys.getPrivate());
//    // common, orgUnit, org, locality, state, country
//    X500Principal principal = new X500Principal( "CN=Ole Nordmann, OU=ACME, O=Sales, C=NO");
//    X500Name x500name=null;
//    x500name= new X500Name(principal.getEncoded());
//    pkcs10.encodeAndSign(x500name, signature);
//    ByteArrayOutputStream bs = new ByteArrayOutputStream();
//    PrintStream ps = new PrintStream(bs);
//    pkcs10.print(ps);
//    byte[] c = bs.toByteArray();
//    return c;
  }

  public void receiveCheque(Cheque cheque) {

  }
}
