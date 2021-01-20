package org.tokenscript.auth;

import java.security.cert.X509Certificate;

public class VerifierLoader extends CommonLoader {

  private VerifierLoader() {
    super();
  }

  public static Verifier getVerifier(String authenticatorCertDir, String domain) throws Exception {
    VerifierLoader loader = new VerifierLoader();
    X509Certificate authenticatorCert = (X509Certificate) loadCertificate(authenticatorCertDir);
    if (!loader.verifyCert(authenticatorCert)) {
      throw new RuntimeException("could not verify ticket cert");
    }
    return new Verifier(domain, authenticatorCert.getPublicKey());
  }
}
