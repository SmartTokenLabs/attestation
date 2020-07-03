package dk.alexandra.stormbird.cheque;

import java.math.BigInteger;
import org.bouncycastle.jce.PKCS10CertificationRequest;

public class CSRAndSecret {
  private final PKCS10CertificationRequest csr;
  private final BigInteger secret;

  public CSRAndSecret(PKCS10CertificationRequest csr, BigInteger secret) {
    this.csr = csr;
    this.secret = secret;
  }

  public PKCS10CertificationRequest getCsr() {
    return csr;
  }

  public BigInteger getSecret() {
    return secret;
  }

}
