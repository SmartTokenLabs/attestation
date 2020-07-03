package dk.alexandra.stormbird.cheque;

import static org.bouncycastle.asn1.x500.style.BCStyle.CN;

import com.objsys.asn1j.runtime.Asn1OctetString;
import com.sun.jarsigner.ContentSigner;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Random;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKKeyFactory.X509;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECPoint.Fp;
import sun.security.pkcs10.PKCS10;
import sun.security.x509.X500Name;

public class Receiver {
  private final String address;
  private final Crypto crypto;
  private final KeyPair keys;
  private static final X9ECParameters curve = SECNamedCurves.getByName ("secp256k1");
  private static final ECDomainParameters domain = new ECDomainParameters (curve.getCurve (), curve.getG (), curve.getN (), curve.getH ());

  public Receiver(String address, KeyPair keys, Crypto crypto) {
    this.address = address;
    this.keys = keys;
    this.crypto = crypto;
  }

  /**
   * DER encoded CSR with ECDSA SHA256 spec
   */
  public CSRAndSecret createCSR(String identity, int type) throws Exception {
    BigInteger secret = crypto.makeRandomExponent();
    ECPoint identifier = crypto.generateRiddle(type, identity, secret);

    // Encode ETH address as CommonName
    X509Principal name = new X509Principal("CN=" + address);
    byte[] encoding = identifier.getEncoded();
    ASN1Set attributes = new DERSet(new ASN1Encodable[]{
        new DERSequence(new ASN1Encodable[]{
            // Encode encrypted identity as an Octet string attribute
            new DERObjectIdentifier(Util.OID_OCTETSTRING), new DEROctetString(encoding)
        })
//        , new DERSequence(new ASN1Encodable[]{
//            // Integer
//            new DERObjectIdentifier("1.3.6.1.4.1.1466.115.121.1.27"), new DERSet( new DERInteger(type))
//          new DEROctetString(secret), new DERInteger(type)
    });
    // OID for ECDSA with SHA256
    PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Util.OID_SHA256ECDSA, name, keys.getPublic(), attributes, keys.getPrivate());
    return new CSRAndSecret(csr, secret);
  }

  public Proof redeemCheque(ChequeAndSecret chequeAndSecret, X509Certificate cert, BigInteger secret) throws Exception {
    ECPoint decodedRiddle = crypto.decodePoint(chequeAndSecret.getCheque().cheque.riddle.value);
    BigInteger x = secret.modInverse(crypto.curveOrder).multiply(chequeAndSecret.getSecret()).mod(crypto.curveOrder);
    // It now holds that identifier.multiply(x) = riddle
    ECPoint identifier = crypto.decodePoint(Util.getIdentifierFromCert(cert));
    List<byte[]> proof = crypto.computeProof(identifier, decodedRiddle, x);
    Proof res = new Proof(new Asn1OctetString(proof.get(0)), new Asn1OctetString(proof.get(1)),
        new Asn1OctetString(proof.get(2)), new Asn1OctetString(proof.get(3)));
    return res;
  }
}
