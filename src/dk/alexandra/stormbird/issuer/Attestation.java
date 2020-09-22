package dk.alexandra.stormbird.issuer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.json.JSONObject;

public class Attestation {
  public static final String ECDSA_CURVE = "secp256k1";
  public static final String OID_SIGNATURE_ALG = "1.2.840.10045.2.1"; // OID for elliptic curve crypto
  public static final X9ECParameters CURVE_PARAM = SECNamedCurves.getByName(ECDSA_CURVE);
  private final AsymmetricCipherKeyPair serverKey;

  public Attestation(AsymmetricCipherKeyPair serverKey) {
    this.serverKey = serverKey;
  }


  public byte[] constructAttestation(String request, String response, byte[] signature, byte[] publicKey) {
    try {
      JSONObject requestJson = new JSONObject(request);
      JSONObject responseJson = new JSONObject(response);
      Certificate cert = constructAttestation(requestJson, responseJson, signature, restoreKey(publicKey));
      return cert.getEncoded();
    } catch (IOException e) {
      throw new RuntimeException("Could not decode public key");
    } catch (CertificateEncodingException e) {
      throw new RuntimeException("Could not encode cert");
    }
  }

  public Certificate constructAttestation(JSONObject request, JSONObject response, byte[] signature, AsymmetricKeyParameter userKey) {
    if (!SignatureUtil.verify(request.toString().getBytes(StandardCharsets.UTF_8), signature, userKey)) {
      throw new IllegalArgumentException("Request signature is not valid");
    }
    return null;
  }



  /**
   * Extract the public key from its DER encoded BITString
   * @param input
   * @return
   */
  public static AsymmetricKeyParameter restoreKey(byte[] input) throws IOException {
    AlgorithmIdentifier identifierEnc = new AlgorithmIdentifier(new ASN1ObjectIdentifier(OID_SIGNATURE_ALG), CURVE_PARAM.toASN1Primitive());
    ASN1BitString keyEnc = DERBitString.getInstance(input);
    ASN1Sequence spkiEnc = new DERSequence(new ASN1Encodable[] {identifierEnc, keyEnc});
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiEnc);
    return PublicKeyFactory.createKey(spki);
  }
}

