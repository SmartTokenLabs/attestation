package dk.alexandra.stormbird.cheque;

import dk.alexandra.stormbird.cheque.asnobjects.Proof;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class CA {
  private final KeyPair keys;
  private final Crypto crypto;
  private static final X9ECParameters curve = SECNamedCurves.getByName (Crypto.ECDSA_CURVE);

  public CA(Crypto crypto, KeyPair keys ) {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    this.crypto = crypto;
    this.keys = keys;
  }

  public boolean verifyRequest(CSRAndSecret csrAndSecret) throws Exception {
    // TODO verify that Bob holds the mail address
    // CHECK: ZK proof
    Proof proof = csrAndSecret.getProof();
    if (!crypto.verifyProof(Arrays.asList(
        proof.base.value, proof.riddle.value, proof.challengePoint.value, proof.reponseValue.value))) {
      System.err.println("Proof did not verify");
      return false;
    }
    // CHECK: Signature on overall request
    byte[] signedValue = Util.getBytes(Arrays.asList(
        Util.getAsnBytes(Arrays.asList(csrAndSecret.getProof())),
        csrAndSecret.getCsr().getEncoded()));
    if (!crypto.verifyBytes(signedValue, csrAndSecret.getProofSignature(), csrAndSecret.getCsr().getPublicKey())) {
      System.err.println("The signature on CSR request is not valid");
      return false;
    }
    return true;
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
    serverCertGen.setSubjectDN(X509Name.getInstance(csr.getCertificationRequestInfo().getSubject()));
    serverCertGen.setPublicKey(csr.getPublicKey());
    serverCertGen.setSignatureAlgorithm(Util.OID_SHA256ECDSA);
    ASN1Set attributes = csr.getCertificationRequestInfo().getAttributes();
    // We encode the attributes of the CSR as an Extension to be compatible with X509v3
    for (ASN1Encodable current : attributes.toArray()) {
      // The encoding is a sequence of triples of object identifier, boolean, and object
      DERSequence currentOb = (DERSequence) current.toASN1Primitive();
      ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) currentOb.getObjectAt(0);
      ASN1Set object = (ASN1Set) currentOb.getObjectAt(1).toASN1Primitive();
      // CRITICAL is always set to true and we need to get the first object in the set
      serverCertGen.addExtension(oid, true, object.getObjectAt(0));
    }
    return serverCertGen.generateX509Certificate(keys.getPrivate(), "BC");
  }

}
