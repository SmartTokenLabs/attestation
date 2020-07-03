package dk.alexandra.stormbird.cheque;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

public class CA {
  private final SecureRandom rand;
  private final KeyPair keys;
  private final String address;
  private static final X9ECParameters curve = SECNamedCurves.getByName ("secp256k1");
  private static final ECDomainParameters domain = new ECDomainParameters (curve.getCurve (), curve.getG (), curve.getN (), curve.getH ());

  public CA(String address, KeyPair keys ) {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    this.address = address;
    this.keys = keys;
    rand = new SecureRandom(); // This MUST not be deterministic. Java self-seeds SecureRandom
  }

  public X509Certificate makeCert(PKCS10CertificationRequest csr) throws Exception {
    if (!csr.verify()) {
      throw new RuntimeException("CSR is not valid");
    }

    X509V3CertificateGenerator serverCertGen = new X509V3CertificateGenerator();
    serverCertGen.setSerialNumber(new BigInteger("123456789"));
    // X509Certificate caCert=null;
    serverCertGen.setIssuerDN(new X509Name("CN=Alex"));
    serverCertGen.setNotBefore(new Date());
    serverCertGen.setNotAfter(new Date(System.currentTimeMillis() + 2592000000L));
    serverCertGen.setSubjectDN(csr.getCertificationRequestInfo().getSubject());
    serverCertGen.setPublicKey(keys.getPublic());
    serverCertGen.setSignatureAlgorithm("SHA256withECDSA");
    ASN1Set attributes = csr.getCertificationRequestInfo().getAttributes();
    for (ASN1Encodable current : attributes.toArray()) {
      // The encoding is a sequence of pairs
      DERSequence currentOb = (DERSequence) current.toASN1Object();
      DERObjectIdentifier oid = (DERObjectIdentifier) currentOb.getObjectAt(0);
      DERObject object = (DERObject) currentOb.getObjectAt(1);
      serverCertGen.addExtension(oid, true, object);
    }
    return serverCertGen.generateX509Certificate(keys.getPrivate(), "BC");
  }

}
