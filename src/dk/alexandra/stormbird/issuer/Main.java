package dk.alexandra.stormbird.issuer;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
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
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.Keccak.Digest256;
import org.json.JSONObject;

public class Main {
  public static final String ECDSA_CURVE = "secp256k1";
  public static final String OID_SIGNATURE_ALG = "1.2.840.10045.2.1"; // OID for elliptic curve crypto
  public static final X9ECParameters CURVE_PARAM = SECNamedCurves.getByName(ECDSA_CURVE);
  private final AsymmetricCipherKeyPair serverKey;

  public Main(AsymmetricCipherKeyPair serverKey) {
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
    if (!verifyRequest(request, signature, userKey)) {
      throw new IllegalArgumentException("Request signature is not valid");
    }
    return null;
  }

  private static boolean verifyRequest(JSONObject request, byte[] signature, AsymmetricKeyParameter publicKey) {
    byte[] unsigned = request.toString().getBytes(StandardCharsets.UTF_8);
    Digest256 digest = new Keccak.Digest256();
    byte[] digestBytes = digest.digest(unsigned);
    return verifyHashed(digestBytes, signature, publicKey);
  }

  private static boolean verifyHashed(byte[] digest, byte[] signature, AsymmetricKeyParameter key) {
    try {
      ASN1InputStream input = new ASN1InputStream(signature);
      ASN1Sequence seq = ASN1Sequence.getInstance(input.readObject());
      BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
      BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
      // Normalize number s
      BigInteger half_curve = ((ECKeyParameters) key).getParameters().getCurve().getOrder().shiftRight(1);
      if (s.compareTo(half_curve) > 0) {
        s = ((ECKeyParameters) key).getParameters().getN().subtract(s);
      }
      ECDSASigner signer = new ECDSASigner();
      signer.init(false, key);
      return signer.verifySignature(digest, r, s);
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
    AlgorithmIdentifier identifierEnc = new AlgorithmIdentifier(new ASN1ObjectIdentifier(OID_SIGNATURE_ALG), CURVE_PARAM.toASN1Primitive());
    ASN1BitString keyEnc = DERBitString.getInstance(input);
    ASN1Sequence spkiEnc = new DERSequence(new ASN1Encodable[] {identifierEnc, keyEnc});
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiEnc);
    return PublicKeyFactory.createKey(spki);
  }
}

