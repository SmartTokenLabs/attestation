package dk.alexandra.stormbird.issuer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
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
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.json.JSONObject;

public class Attestation {
  public static final String OID_SHA256ECDSA = "1.2.840.10045.4.3.2";
  public static final String OID_ECDSA = "1.2.840.10045.4";// "1.2.840.113635.100.2.7";
  public static final String OID_SECP256R1 = "1.2.840.10045.3.1.7";
  public static final String OID_SIGNATURE_ALG = "1.2.840.10045.2.1"; // OID for elliptic curve crypto
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
  public Attestation(AsymmetricCipherKeyPair serverKey, X500Name serverInfo, long lifeTime) {
    this.serverKey = serverKey;
    this.serverInfo = serverInfo;
    this.lifeTime = lifeTime;
    try {
//      serverSigningAlgo = new AlgorithmIdentifier(
//          new ASN1ObjectIdentifier(OID_SIGNATURE_ALG), CURVE_PARAM.toASN1Primitive());
      AlgorithmIdentifier identifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(OID_SHA256ECDSA));
      AlgorithmIdentifier hashIdentifier = new DefaultDigestAlgorithmIdentifierFinder().find(identifier);
      BcECContentSignerBuilder contentBuilder = new BcECContentSignerBuilder(identifier, hashIdentifier);
      signer = contentBuilder.build(serverKey.getPrivate());
      serverSigningAlgo = new AlgorithmIdentifier(new ASN1ObjectIdentifier(OID_SHA256ECDSA));
    } catch (OperatorCreationException e) {
      throw new RuntimeException("Could not parse server key");
    }
  }


  /**
   * Constructs a list of X509 attestations to each of the relevant DatasourceName lists of elements
   * in the response json.
   *
   * @param request Json request
   * @param response Json response
   * @param signature DER encoded signature of exactly  the json request string encoded as UTF-8 using a Secp256k1 key with Keccak
   * @param publicKey DER encoded public key (SubjectPublicKeyInfo object)
   * @return List of DER encoded x509 attestations
   */
  public List<byte[]> constructAttestation(String request, String response, byte[] signature, byte[] publicKey) {
    try {
      AsymmetricKeyParameter userKey = restoreKey(publicKey);
      byte[] bytes = request.getBytes(StandardCharsets.UTF_8);
      if (!SignatureUtil.verifyKeccak(bytes, signature, userKey)) {
        throw new IllegalArgumentException("Request signature is not valid");
      }
      JSONObject requestJson = new JSONObject(request);
      JSONObject responseJson = new JSONObject(response);
      List<X509CertificateHolder> certs = constructAttestationWOVerification(requestJson, responseJson, signature, userKey);
      List<byte[]> res = new ArrayList<>();
      for (X509CertificateHolder current : certs) {
        res.add(current.getEncoded());
      }
      return res;
    } catch (IOException e) {
      throw new RuntimeException("Could not decode public key");
    }
  }

  List<X509CertificateHolder> constructAttestationWOVerification(JSONObject request, JSONObject response, byte[] signature, AsymmetricKeyParameter userKey) {
    List<X509CertificateHolder> res = new ArrayList<>();
    Parser parser = new Parser(request, response);
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

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(userKey);
        // todo hack to create a valid spki
        spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier(OID_ECDSA)),
            spki.getPublicKeyData());
        certBuilder.setSubjectPublicKeyInfo(spki);
        certBuilder.setSubject(subjectNames.get(currentAttName));
        certBuilder.setExtensions(subjectExtensions.get(currentAttName));
        TBSCertificate tbsCert = certBuilder.generateTBSCertificate();
        res.add(new X509CertificateHolder(constructSignedAttestation(tbsCert)));

        // To ensure that we get a new serial number for every cert
        Thread.sleep(1);
      } catch (IOException e) {
        throw new RuntimeException("Could not parse server key");
      } catch (InterruptedException e) {
        throw new RuntimeException("Could not sleep");
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

  /**
   * Extract the public key from its DER encoded BITString
   * @param input
   * @return
   */
  public static AsymmetricKeyParameter restoreKey(byte[] input) throws IOException {
    AlgorithmIdentifier identifierEnc = new AlgorithmIdentifier(
        // OID_SIGNATURE_ALG is needed here otherwise the reconstruction fails
        new ASN1ObjectIdentifier(OID_SIGNATURE_ALG), CURVE_PARAM.toASN1Primitive());
    ASN1BitString keyEnc = DERBitString.getInstance(input);
    ASN1Sequence spkiEnc = new DERSequence(new ASN1Encodable[] {identifierEnc, keyEnc});
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiEnc);
    return PublicKeyFactory.createKey(spki);
  }
}

