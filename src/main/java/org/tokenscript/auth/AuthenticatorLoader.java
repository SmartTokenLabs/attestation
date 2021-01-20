package org.tokenscript.auth;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.core.SignatureUtility;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import org.devcon.ticket.TicketDecoder;

public class AuthenticatorLoader extends CommonLoader {
  private AuthenticatorLoader() {
    super();
  }

  public static Authenticator getTicketAuthenticator(String signingKeyDir, String authenticatorCertDir, String attestorCertDir, String ticketCertDir) throws Exception {
    AuthenticatorLoader loader = new AuthenticatorLoader();
    X509Certificate ticketCert = (X509Certificate) loadCertificate(ticketCertDir);
    if (!loader.verifyCert(ticketCert)) {
      throw new RuntimeException("could not verify ticket cert");
    }
    byte[] encoded = ticketCert.getPublicKey().getEncoded();
    AttestableObjectDecoder ticketDecoder = new TicketDecoder(SignatureUtility.restoreKeyFromSPKI(encoded));
    return loader.loadAuthenticator(signingKeyDir, authenticatorCertDir, attestorCertDir, ticketDecoder);
  }

  public static Authenticator getAuthenticator(String signingKeyDir, String authenticatorCertDir, String attestorCertDir, AttestableObjectDecoder decoder) throws Exception {
    AuthenticatorLoader loader = new AuthenticatorLoader();
    return loader.loadAuthenticator(signingKeyDir, authenticatorCertDir, attestorCertDir, decoder);
  }

  private Authenticator loadAuthenticator(String signingKeyDir, String authenticatorCertDir, String attestorCertDir, AttestableObjectDecoder decoder) throws Exception {
    X509Certificate attestorCert = (X509Certificate) loadCertificate(attestorCertDir);
    if (!verifyCert(attestorCert)) {
      throw new RuntimeException("could not verify attestor cert");
    }
    X509Certificate cert = (X509Certificate) loadCertificate(authenticatorCertDir);
    KeyPair authenticatorKeyPair = loadVerifiedKeyPair(cert, signingKeyDir);
    String authenticatorDomain = getCommonName(cert.getSubjectDN());
    return new Authenticator(decoder, attestorCert.getPublicKey(), authenticatorDomain, authenticatorKeyPair);
  }

  private String getCommonName(Principal subjectDN) {
    String name = subjectDN.getName();
    int CNindex = name.indexOf("CN=");
    if (CNindex < 0) {
      throw new IllegalArgumentException("No common name in subject DN");
    }
    String cnSubstring = name.substring(CNindex);
    int endIndex = cnSubstring.indexOf(",");
    if (endIndex < 0) {
      // CN ends the subjectDN
     endIndex = cnSubstring.length();
    }
    return cnSubstring.substring(CNindex+3, endIndex);
  }

  static KeyPair loadVerifiedKeyPair(X509Certificate cert, String privDir) throws Exception {
    PrivateKey privateKey = loadPrivateKey(privDir, cert.getPublicKey().getAlgorithm());
    if (!verifyKeyAndCert(privateKey, cert)) {
      throw new RuntimeException("Could not verify authenticator cert");
    }
    return new KeyPair(cert.getPublicKey(), privateKey);
  }

  private static PrivateKey loadPrivateKey(String privateKeyDir, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] privateKeyPemBytes = Files.readAllBytes(Paths.get(privateKeyDir));
    PKCS8EncodedKeySpec privateKeyPKCS8 = new PKCS8EncodedKeySpec(privateKeyPemBytes);
    KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
    PrivateKey privateKey = keyFactory.generatePrivate(privateKeyPKCS8);
    return privateKey;
  }

  private static boolean verifyKeyAndCert(PrivateKey key, X509Certificate cert) {
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

  private static boolean verifyKeysMatch(PrivateKey privateKey, PublicKey publicKey) throws Exception {
    String message = "some arbitrary message";
    String algorithm = getAlgorithm(publicKey);
    byte[] signature = computeSignature(privateKey, message, algorithm);
    return verifySignature(publicKey, message, signature, algorithm);
  }

  private static byte[] computeSignature(PrivateKey privateKey, String message, String algorithm) throws Exception {
    Signature signer = Signature.getInstance(algorithm);
    signer.initSign(privateKey);
    signer.update(message.getBytes(StandardCharsets.UTF_8));
    return signer.sign();
  }

  private static boolean verifySignature(PublicKey publicKey, String message, byte[] signature, String algorithm) throws Exception{
    Signature verifier = Signature.getInstance(algorithm);
    verifier.initVerify(publicKey);
    verifier.update(message.getBytes(StandardCharsets.UTF_8));
    if (!verifier.verify(signature)) {
      return false;
    }
    return true;
  }

  private static String getAlgorithm(PublicKey pk) {
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
}
