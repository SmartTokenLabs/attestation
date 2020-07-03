package dk.alexandra.stormbird.cheque;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.jce.PKCS10CertificationRequest;

public class Util {
  public static final int CHARS_IN_LINE = 65;

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
