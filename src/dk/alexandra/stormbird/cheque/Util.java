package dk.alexandra.stormbird.cheque;

import com.objsys.asn1j.runtime.Asn1BerEncodeBuffer;
import com.objsys.asn1j.runtime.Asn1Type;
import dk.alexandra.stormbird.cheque.asnobjects.SignedCheque;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.PKCS10CertificationRequest;

public class Util {
  public static final int CHARS_IN_LINE = 65;
  public static final String OID_SHA256ECDSA = "1.2.840.10045.4.3.2";
  public static final String OID_OCTETSTRING = "1.3.6.1.4.1.1466.115.121.1.40";

  public static byte[] encodeASNObject(Asn1Type object) {
    Asn1BerEncodeBuffer outputStream = new Asn1BerEncodeBuffer();
    object.encode(outputStream);
    return outputStream.getMsgCopy();
  }

  public static byte[] getIdentifierFromCert(X509Certificate cert) throws Exception {
    byte[] byteIdentifier = cert.getExtensionValue(Util.OID_OCTETSTRING);
    ASN1InputStream input = new ASN1InputStream(byteIdentifier);
    DEROctetString object = (DEROctetString) input.readObject();
    // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
    input = new ASN1InputStream(object.getOctets());
    object = (DEROctetString) input.readObject();
    return object.getOctets();
  }

  public static String printCheque(SignedCheque input) throws Exception {
    byte[] encodedCert = Base64.getEncoder().encode(Util.encodeASNObject(input));
    StringBuilder builder = new StringBuilder();
    builder.append("-----BEGIN CHEQUE-----\n");
    addBytes(builder, encodedCert);
    builder.append("-----END CHEQUE-----");
    return builder.toString();
  }

  public static String printDERCert(X509Certificate input) throws Exception {
    byte[] encodedCert = Base64.getEncoder().encode(input.getEncoded());
    StringBuilder builder = new StringBuilder();
    builder.append("-----BEGIN CERTIFICATE-----\n");
    addBytes(builder, encodedCert);
    builder.append("-----END CERTIFICATE-----");
    return builder.toString();
  }

  public static String printDERCSR(PKCS10CertificationRequest input) throws Exception {
    byte[] encodedCsr = Base64.getEncoder().encode(input.getEncoded());
    StringBuilder builder = new StringBuilder();
    builder.append("-----BEGIN CERTIFICATE REQUEST-----\n");
    addBytes(builder, encodedCsr);
    builder.append("-----END CERTIFICATE REQUEST-----");
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
