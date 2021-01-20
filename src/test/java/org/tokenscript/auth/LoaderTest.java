package org.tokenscript.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class LoaderTest {
  /**
   * Generated with openssl through
   * openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 -keyout src/test/data/rsaPrivateKey.key -out src/test/data/certificate.crt
   * % openssl pkcs8 -topk8 -inform PEM -outform DER -in src/test/data/rsaPrivateKey.key -out src/test/data/signingKey.pkcs8 -nocrypt
   */
  private static final String privatePkcs8TestKeyDir = "src/test/data/signingKey.pkcs8";
  private static final String authenticatorCertDir = "src/test/data/authCert.crt";
  private static final String attestorCertDir = "src/test/data/attestorCert.crt";
  private static final String ticketCertDir = "src/test/data/ticketCert.crt";
  private static final String testTrustStore = "src/test/data/testcacerts";

  private static final ObjectMapper mapper = new ObjectMapper();

  @BeforeAll
  public static void setup() throws Exception {
    // Change truststore to test trust store to not modify true system files
    Field trustStoreDir = AuthenticatorLoader.class.getDeclaredField("trustStoreDir");
    setPrivate(trustStoreDir, testTrustStore);

    // Add cert to truststore since they are all selfsigned for tests
    // Using default password for truststore
    KeyStore keyStore = AuthenticatorLoader.getTrustStore("changeit");
    keyStore.setCertificateEntry("authenticatorCert", AuthenticatorLoader.loadCertificate(authenticatorCertDir));
    keyStore.setCertificateEntry("attestorCert", AuthenticatorLoader.loadCertificate(attestorCertDir));
    keyStore.setCertificateEntry("ticketCert", AuthenticatorLoader.loadCertificate(ticketCertDir));
    OutputStream os = Files.newOutputStream(Paths.get(testTrustStore));
    keyStore.store(os, "changeit".toCharArray());
  }

  static void setPrivate(Field field, Object newValue) throws Exception {
    field.setAccessible(true);
    field.set(null, newValue);
  }

  @Test
  public void sunshine() throws Exception {
    AuthenticatorLoader loader = new AuthenticatorLoader();
    Authenticator authenticator = loader.loadTicketAuthenticator(
        privatePkcs8TestKeyDir, authenticatorCertDir, attestorCertDir, ticketCertDir);
//    Verifier verifier = new Verifier("https://test.test.se", authenticatorKeys.getPublic());
//    AuthenticatorTest.setupKeys();
//    UseAttestableRequest request = AuthenticatorTest.makeValidRequest();
//    byte[] requestBytes = mapper.writeValueAsBytes(request);
//    byte[] jwtResponse = authenticator.validateRequest(requestBytes);
//    assertFalse(Arrays.equals(AuthenticatorTest.failResponse, jwtResponse));
//    assertTrue(verifier.verifyToken(jwtResponse));
  }
}
