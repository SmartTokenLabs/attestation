package dk.alexandra.trulioo.issuer;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public class ASN1Util {
  public static final int CHARS_IN_LINE = 65;

  /**
   * Extract the public key from its DER encoded BITString
   * @param input
   * @return
   */
  public static AsymmetricKeyParameter restorePublicKey(byte[] input, X9ECParameters parameters, String oid) throws IOException {
    AlgorithmIdentifier identifierEnc = new AlgorithmIdentifier(
        new ASN1ObjectIdentifier(oid), parameters.toASN1Primitive());
    ASN1BitString keyEnc = DERBitString.getInstance(input);
    ASN1Sequence spkiEnc = new DERSequence(new ASN1Encodable[] {identifierEnc, keyEnc});
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiEnc);
    return PublicKeyFactory.createKey(spki);
  }

  /**
   * Extract the private key from its PEM, base 64 encoding
   * @param input
   * @return
   */
  public static AsymmetricKeyParameter restoreBase64PrivateKey(String input) throws IOException {
    List<String> lines = input.lines().collect(Collectors.toList());
    // skip first and last line
    List<String> arr = lines.subList(1, lines.size()-1);
    StringBuffer buf = new StringBuffer();
    for (int i = 0; i < arr.size(); i++) {
      buf.append(arr.get(i));
    }
    return PrivateKeyFactory.createKey(Base64.getDecoder().decode(buf.toString()));
  }

  /**
   * Extract the public key from its PEM, base 64 encoding
   * @param input
   * @return
   */
  public static AsymmetricKeyParameter restoreBase64PublicKey(String input) throws IOException {
    List<String> lines = input.lines().collect(Collectors.toList());
    // skip first and last line
    List<String> arr = lines.subList(1, lines.size()-1);
    StringBuffer buf = new StringBuffer();
    for (int i = 0; i < arr.size(); i++) {
      buf.append(arr.get(i));
    }
    return PublicKeyFactory.createKey(Base64.getDecoder().decode(buf.toString()));
  }

  public static String printDER(byte[] input, String type) {
    byte[] encodedCert = Base64.getEncoder().encode(input);
    StringBuilder builder = new StringBuilder();
    builder.append("-----BEGIN "+ type +"-----\n");
    addBytes(builder, encodedCert);
    builder.append("-----END "+ type +"-----");
    return builder.toString();
  }

  private static void addBytes(StringBuilder builder, byte[] encoding) {
    int start = 0;
    while (start < encoding.length) {
      int end = encoding.length - (start + CHARS_IN_LINE) > 0 ?
          start + CHARS_IN_LINE : encoding.length;
      builder.append(new String(Arrays.copyOfRange(encoding, start, end)));
      builder.append('\n');
      start += CHARS_IN_LINE;
    }
  }
}
