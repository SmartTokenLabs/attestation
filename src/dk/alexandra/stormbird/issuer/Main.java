package dk.alexandra.stormbird.issuer;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.json.JSONObject;

public class Main {
  public Main() {}

  public byte[] constructAttestation(byte[] rawCsr, byte[] truliooResponse) {
    ASN1InputStream input = new ASN1InputStream(rawCsr);
    try {
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      CertificationRequest csr = new CertificationRequest(asn1);
      JSONObject json = new JSONObject(Arrays.toString(truliooResponse));
      Certificate cert = constructAttestation(csr, json);

      return cert.getEncoded();
    } catch (IOException e) {
      throw new RuntimeException("Could not decode CSR");
    } catch (CertificateEncodingException e) {
      throw new RuntimeException("Could not encode cert");
    }


  }

  public Certificate constructAttestation(CertificationRequest csr, JSONObject truliooResponse) {
    if (!verifyCSR(csr)) {
      throw new IllegalArgumentException("CSR is not valid");
    }
    return null;
  }

  private boolean verifyCSR(CertificationRequest csr) {
    try {
//      if (!csr.getCertificationRequestInfo())
        return false;
    } catch (Exception e) {
      return false;
    }
//    return true;
  }
}

