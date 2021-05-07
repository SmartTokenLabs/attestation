package dk.alexandra.trulioo.issuer;

import com.alphawallet.attestation.core.ExceptionUtil;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.json.JSONObject;

public class Attestor {
  private static final Logger logger = LogManager.getLogger(Attestor.class);

  public static final String OID_ECDSA = "1.2.840.10045.4";
  public static final String OID_SECP256R1 = "1.2.840.10045.3.1.7";
  public static final String OID_SIGNATURE_ALG = "1.2.840.10045.2.1"; // OID for elliptic curve crypto
  public static final String OID_SHA256ECDSA = "1.2.840.10045.4.3.2";
  public static final String ECDSA_CURVE = "secp256k1";
  public static final X9ECParameters CURVE_PARAM = SECNamedCurves.getByName(ECDSA_CURVE);
  private final AsymmetricCipherKeyPair serverKey;
  private final X500Name serverInfo;
  private final long lifeTime;
  private final AlgorithmIdentifier serverSigningAlgo;
  private final ContentSigner signer;

  /**
   *
   * @param serverKey The key used for signing the cert
   * @param serverInfo The information about the issuer to include in the cert
   * @param lifeTime Lifetime of cert in milliseconds
   */
  public Attestor(AsymmetricCipherKeyPair serverKey, X500Name serverInfo, long lifeTime) {
    this.serverKey = serverKey;
    this.serverInfo = serverInfo;
    this.lifeTime = lifeTime;
    try {
//      serverSigningAlgo = new AlgorithmIdentifier(
//          new ASN1ObjectIdentifier(OID_SIGNATURE_ALG), CURVE_PARAM.toASN1Primitive());
      serverSigningAlgo = new AlgorithmIdentifier(new ASN1ObjectIdentifier(OID_SHA256ECDSA));
      AlgorithmIdentifier hashIdentifier = new DefaultDigestAlgorithmIdentifierFinder().find(serverSigningAlgo);
      BcECContentSignerBuilder contentBuilder = new BcECContentSignerBuilder(serverSigningAlgo, hashIdentifier);
      signer = contentBuilder.build(serverKey.getPrivate());
    } catch (OperatorCreationException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not parse server key", e);
    }
  }

  /**
   * Constructs a list of X509 attestations to each of the relevant DatasourceName lists of elements
   * in the response json.
   *
   * @param request Json request in a Sring - verification request that was sent to Trulioo Global Gateway†
   * @param verifyRecord Json object of the Record in verifyResponse, from Trulioo Global Gateway‡
   * @param signature DER encoded signature of exactly the json request string encoded as UTF-8 using a Secp256k1 key with Keccak
   * @param userPK user's public key (SubjectPublicKeyInfo object)
   * @return List of DER encoded x509 attestations
   *
   * † An example can be found https://developer.trulioo.com/docs/identity-verification-step-6-verify
   * ‡ Observe the "Record" in https://developer.trulioo.com/docs/identity-verification-verify-response
   */

  public List<X509CertificateHolder> constructAttestations(String request, JSONObject verifyRecord, byte[] signature, AsymmetricKeyParameter userPK) {
    if (!SignatureUtil.verifySha256(request.getBytes(StandardCharsets.UTF_8), signature, userPK)) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Request signature verification failed. "
      + "Make sure that your message is unaltered, signature is created by hashing the message with SHA256"
      + "and using a key of secp256k1 type."));
    }
    List<X509CertificateHolder> res = new ArrayList<>();
    Parser parser = new Parser(new JSONObject(request), verifyRecord);
    Map<String, X500Name> subjectNames = parser.getX500Names();
    Map<String, Extensions> subjectExtensions = parser.getExtensions();
    for (String currentAttName : subjectNames.keySet()) {
      try {
        long time = System.currentTimeMillis();
        V3TBSCertificateGenerator certBuilder = new V3TBSCertificateGenerator();
        certBuilder.setSignature(serverSigningAlgo);
        certBuilder.setIssuer(serverInfo);

        certBuilder.setSerialNumber(new ASN1Integer(time));

        certBuilder.setStartDate(new Time(new Date(time)));
        certBuilder.setEndDate(new Time(new Date(time + lifeTime)));

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(userPK);
//        // todo hack to create a valid spki without ECNamedParameters
//        spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier(OID_ECDSA)),
//            spki.getPublicKeyData());
        certBuilder.setSubjectPublicKeyInfo(spki);
        certBuilder.setSubject(subjectNames.get(currentAttName));
        certBuilder.setExtensions(subjectExtensions.get(currentAttName));
        TBSCertificate tbsCert = certBuilder.generateTBSCertificate();
        res.add(new X509CertificateHolder(constructSignedAttestation(tbsCert)));

        // To ensure that we get a new serial number for every cert
        Thread.sleep(1);
      } catch (IOException e) {
        throw ExceptionUtil.makeRuntimeException(logger, "Could not parse server key", e);
      } catch (InterruptedException e) {
        throw ExceptionUtil.makeRuntimeException(logger, "Could not sleep", e);
      }
    }
    return res;
  }

  private byte[] constructSignedAttestation(TBSCertificate unsignedAtt) {
    try {
      byte[] rawAtt = unsignedAtt.getEncoded();
      byte[] signature = SignatureUtil.signSha256(rawAtt, serverKey.getPrivate());
      ASN1EncodableVector res = new ASN1EncodableVector();
      res.add(ASN1Primitive.fromByteArray(rawAtt));
      res.add(serverSigningAlgo);
      res.add(new DERBitString(signature));
      return new DERSequence(res).getEncoded();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

}

