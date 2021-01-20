package org.tokenscript.auth;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.core.SignatureUtility;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import org.devcon.ticket.TicketDecoder;

public class AuthenticatorLoader {
  private static String trustStoreDir = System.getenv("JAVA_HOME") + "/lib/security/cacerts";

  public AuthenticatorLoader() {
    // Enable OCSP verification to ensure certs have not been revoked
    System.setProperty("com.sun.net.ssl.checkRevocation", "true");
    Security.setProperty("ocsp.enable", "true");
  }

  public Authenticator loadTicketAuthenticator(String signingKeyDir, String authenticatorCertDir, String attestorCertDir, String ticketCertDir) throws Exception {
    X509Certificate ticketCert = (X509Certificate) loadCertificate(ticketCertDir);
    if (!verifyCert(ticketCert)) {
      throw new RuntimeException("could not verify ticket cert");
    }
    byte[] encoded = ticketCert.getPublicKey().getEncoded();
    AttestableObjectDecoder ticketDecoder = new TicketDecoder(SignatureUtility.restoreKeyFromSPKI(encoded));
    return loadAuthenticator(signingKeyDir, authenticatorCertDir, attestorCertDir, ticketDecoder);
  }

  public Authenticator loadAuthenticator(String signingKeyDir, String authenticatorCertDir, String attestorCertDir, AttestableObjectDecoder decoder) throws Exception {
    X509Certificate attestorCert = (X509Certificate) loadCertificate(attestorCertDir);
    if (!verifyCert(attestorCert)) {
      throw new RuntimeException("could not verify attestor cert");
    }
    X509Certificate authenticatorCert = (X509Certificate) loadCertificate(authenticatorCertDir);
    PrivateKey signingKey = loadPrivateKey(signingKeyDir, authenticatorCert.getPublicKey().getAlgorithm());
    if (!verifyKeyAndCert(signingKey, authenticatorCert)) {
      throw new RuntimeException("Could not verify authenticator cert");
    }
    KeyPair authenticatorKeyPair = new KeyPair(authenticatorCert.getPublicKey(), signingKey);
    return new Authenticator(decoder, attestorCert.getPublicKey(), authenticatorKeyPair);
  }

  private PrivateKey loadPrivateKey(String privateKeyDir, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] privateKeyPemBytes = Files.readAllBytes(Paths.get(privateKeyDir));
    PKCS8EncodedKeySpec privateKeyPKCS8 = new PKCS8EncodedKeySpec(privateKeyPemBytes);
    KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
    PrivateKey privateKey = keyFactory.generatePrivate(privateKeyPKCS8);
    return privateKey;
  }

  static Certificate loadCertificate(String certificateDir) throws CertificateException, FileNotFoundException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    FileInputStream inputStream = new FileInputStream(certificateDir);
    Certificate cert = certificateFactory.generateCertificate(inputStream);
    return cert;
  }

  private boolean verifyKeyAndCert(PrivateKey key, X509Certificate cert) {
    try {
      verifyCert(cert);
      if (!verifyKeysMatch(key, cert.getPublicKey())) {
        return false;
      }
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private boolean verifyCert(X509Certificate cert) {
    try {
      cert.checkValidity();
      verifyCertSignature(cert);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private boolean verifyKeysMatch(PrivateKey privateKey, PublicKey publicKey) throws Exception {
    String message = "some arbitrary message";
    String algorithm = getAlgorithm(publicKey);
    byte[] signature = computeSignature(privateKey, message, algorithm);
    return verifySignature(publicKey, message, signature, algorithm);
  }

  private String getAlgorithm(PublicKey pk) {
    String algorithm = "SHA512with";
    if (pk instanceof ECPublicKey) {
      algorithm += "ECDSA";
    } else if (pk instanceof RSAPublicKey) {
      algorithm += "RSA";
    } else {
      throw new UnsupportedOperationException("The key used to sign with is not EC or RSA which are currently the only supported types.");
    }
    return algorithm;
  }

  private byte[] computeSignature(PrivateKey privateKey, String message, String algorithm) throws Exception {
    Signature signer = Signature.getInstance(algorithm);
    signer.initSign(privateKey);
    signer.update(message.getBytes(StandardCharsets.UTF_8));
    return signer.sign();
  }

  private boolean verifySignature(PublicKey publicKey, String message, byte[] signature, String algorithm) throws Exception{
    Signature verifier = Signature.getInstance(algorithm);
    verifier.initVerify(publicKey);
    verifier.update(message.getBytes(StandardCharsets.UTF_8));
    if (!verifier.verify(signature)) {
      return false;
    }
    return true;
  }

  /**
   * Verify the certificate in relation to the default truststore.
   * Note that we do not check for revoked certs since we are the one who
   * supplied the certificate to be checked!
   */
  private boolean verifyCertSignature(Certificate cert) throws Exception {
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
