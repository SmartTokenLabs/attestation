package dk.alexandra.trulioo.issuer;

import com.alphawallet.attestation.core.ExceptionUtil;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.Keccak.Digest256;

public class SignatureUtil {
  private static final Logger logger = LogManager.getLogger(SignatureUtil.class);

  public static byte[] signKeccak(byte[] toSign, AsymmetricKeyParameter key) {
    Digest256 digest = new Keccak.Digest256();
    byte[] digestBytes = digest.digest(toSign);
    return signHashed(digestBytes, key);
  }

  public static byte[] signSha256(byte[] toSign, AsymmetricKeyParameter key) {
    byte[] digestBytes = new byte[32];
    Digest digest = new SHA256Digest();
    digest.update(toSign, 0, toSign.length);
    digest.doFinal(digestBytes, 0);
    return signHashed(digestBytes, key);
  }

  static byte[] signHashed(byte[] digest, AsymmetricKeyParameter key) {
    try {
      ECDSASigner signer = new ECDSASigner();
      signer.init(true, key);
      BigInteger[] signature = signer.generateSignature(digest);
      // Normalize number s
      BigInteger half_curve = ((ECKeyParameters) key).getParameters().getCurve().getOrder().shiftRight(1);
      if (signature[1].compareTo(half_curve) > 0) {
        signature[1] = ((ECKeyParameters) key).getParameters().getN().subtract(signature[1]);
      }
      ASN1EncodableVector asn1 = new ASN1EncodableVector();
      asn1.add(new ASN1Integer(signature[0]));
      asn1.add(new ASN1Integer(signature[1]));
      return new DERSequence(asn1).getEncoded();
    } catch (Exception e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not construct signature", e);
    }
  }

  public static boolean verifyKeccak(byte[] request, byte[] signature, AsymmetricKeyParameter publicKey) {
    Digest256 digest = new Keccak.Digest256();
    byte[] digestBytes = digest.digest(request);
    return verifyHashed(digestBytes, signature, publicKey);
  }

  public static boolean verifySha256(byte[] request, byte[] signature, AsymmetricKeyParameter publicKey) {
    byte[] digestBytes = new byte[32];
    Digest digest = new SHA256Digest();
    digest.update(request, 0, request.length);
    digest.doFinal(digestBytes, 0);
    return verifyHashed(digestBytes, signature, publicKey);
  }

  static boolean verifyHashed(byte[] digest, byte[] signature, AsymmetricKeyParameter key) {
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
      throw ExceptionUtil.makeRuntimeException(logger, "Could not verify signature", e);
    }
  }

}
