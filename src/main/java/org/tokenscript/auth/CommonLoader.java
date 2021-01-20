package org.tokenscript.auth;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public abstract class CommonLoader {
  static String trustStoreDir = System.getenv("JAVA_HOME") + "/lib/security/cacerts";

  protected CommonLoader() {
    // Enable OCSP verification to ensure certs have not been revoked
    System.setProperty("com.sun.net.ssl.checkRevocation", "true");
    Security.setProperty("ocsp.enable", "true");
  }

  static Certificate loadCertificate(String certificateDir) throws CertificateException, FileNotFoundException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    FileInputStream inputStream = new FileInputStream(certificateDir);
    Certificate cert = certificateFactory.generateCertificate(inputStream);
    return cert;
  }

  static boolean verifyCert(X509Certificate cert) {
    try {
      cert.checkValidity();
      verifyCertSignature(cert);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Verify the certificate in relation to the default truststore.
   * Note that we do not check for revoked certs since we are the one who
   * supplied the certificate to be checked!
   */
  private static boolean verifyCertSignature(Certificate cert) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    CertPath path = cf.generateCertPath(Arrays.asList(cert));
    CertPathValidator validator = CertPathValidator.getInstance("PKIX");

    KeyStore trustStore = getTrustStore();
    PKIXParameters params = new PKIXParameters(trustStore);
    /* Validate will throw an exception on invalid chains. */
    try {
      PKIXCertPathValidatorResult r = (PKIXCertPathValidatorResult) validator
          .validate(path, params);
    } catch (Exception e) {
      return false;
    }
    return true;
  }

  static KeyStore getTrustStore() throws Exception {
    // Get the trust store as read-only
    return getTrustStore(null);
  }

  static KeyStore getTrustStore(String password) throws Exception {
    KeyStore keystore = KeyStore.getInstance("JKS");
    InputStream is = Files.newInputStream(Paths.get(trustStoreDir));
    // Assume that we are using the default password for the truststore
    if (password != null) {
      keystore.load(is, password.toCharArray());
    } else {
      keystore.load(is, null);
    }
    return keystore;
  }
}
