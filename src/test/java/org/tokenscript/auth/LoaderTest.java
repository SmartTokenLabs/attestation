package org.tokenscript.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.Attestation;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.SignedAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.AttestationCryptoWithEthereumCharacteristics;
import com.alphawallet.attestation.core.SignatureUtility;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.devcon.ticket.Ticket;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class LoaderTest {
  /**
   * Generated with openssl through
   * openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 -keyout src/test/data/rsaPrivateKey.key -out src/test/data/certificate.crt
   * openssl pkcs8 -topk8 -inform PEM -outform DER -in src/test/data/rsaPrivateKey.key -out src/test/data/signingKey.pkcs8 -nocrypt
   * For ticket ECDSA keys are used (to change things up)
   * openssl ecparam -name secp521r1 -genkey -noout -out src/test/data/ticketPrivkey.pem
   * openssl ec -in src/test/data/ticketPrivkey.pem -pubout -out src/test/data/ticketPub.pem
   * openssl req -new -x509 -key src/test/data/ticketPrivKey.pem -out src/test/data/ticketCert.cert -days 4000
   * openssl pkcs8 -topk8 -inform PEM -outform DER -in src/test/data/ticketPrivKey.pem -out src/test/data/ticketPrivKey.pkcs8 -nocrypt
   */
  private static final String authenticatorPrivKeyDir = "src/test/data/authenticatorPrivKey.pkcs8";
  private static final String attestorPrivKeyDir = "src/test/data/attestorPrivKey.pkcs8";
  private static final String ticketPrivKeyDir = "src/test/data/ticketPrivKey.pkcs8";

  private static final String authenticatorCertDir = "src/test/data/authCert.crt";
  private static final String attestorCertDir = "src/test/data/attestorCert.crt";
  private static final String ticketCertDir = "src/test/data/ticketCert.crt";

  private static final String testTrustStore = "src/test/data/testcacerts";

  private static final ObjectMapper mapper = new ObjectMapper();

  @BeforeAll
  public static void setup() throws Exception {
    // Change truststore to test trust store to not modify true system files
    Field trustStoreDir = CommonLoader.class.getDeclaredField("trustStoreDir");
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
  public void sunshineAuthenticator() throws Exception {
    Authenticator authenticator = AuthenticatorLoader.getTicketAuthenticator(
        authenticatorPrivKeyDir, authenticatorCertDir, attestorCertDir, ticketCertDir);
  }

  @Test
  public void sunshineVerifier() throws Exception {
    Verifier verifier = VerifierLoader.getVerifier(authenticatorCertDir, "www.hotelbogota.com");
  }

  @Test
  public void integrationSunshineTest() throws Exception {
    Authenticator authenticator = AuthenticatorLoader.getTicketAuthenticator(
        authenticatorPrivKeyDir, authenticatorCertDir, attestorCertDir, ticketCertDir);
    Verifier verifier = VerifierLoader.getVerifier(authenticatorCertDir, "www.hotelbogota.com");
    UseAttestableRequest request = makeValidRequest();
    byte[] requestBytes = mapper.writeValueAsBytes(request);
    byte[] jwtResponse = authenticator.validateRequest(requestBytes);
    assertFalse(Arrays.equals(AuthenticatorTest.failResponse, jwtResponse));
    assertTrue(verifier.verifyToken(jwtResponse));
  }

  static UseAttestableRequest makeValidRequest() throws Exception {
    SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    AttestationCrypto crypto = new AttestationCryptoWithEthereumCharacteristics(rand);

    AsymmetricCipherKeyPair attestorKeys = loadKeys(attestorCertDir, attestorPrivKeyDir);
    AsymmetricCipherKeyPair authenticatorKeys = loadKeys(authenticatorCertDir, authenticatorPrivKeyDir);
    AsymmetricCipherKeyPair ticketKeys = loadKeys(ticketCertDir, ticketPrivKeyDir);

    BigInteger attestationSecret = new BigInteger("238469");
    String mail = "test@test.dk";
    int conferenceID = 6;
    BigInteger ticketID = new BigInteger("23544587786465");
    int ticketCLass = 0;
    BigInteger ticketSecret = new BigInteger("6546584");
    String verifierDomain = "www.hotelbogota.com";

    Attestation att = HelperTest.makeUnsignedStandardAtt(authenticatorKeys.getPublic(), attestationSecret, mail);
    SignedAttestation signed = new SignedAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(mail, conferenceID, ticketID, ticketCLass, ticketKeys, ticketSecret);
    AttestedObject<Ticket> attestedTicket = new AttestedObject<Ticket>(ticket, signed,
        authenticatorKeys, attestationSecret, ticketSecret, crypto);
    UseAttestableRequest request = new UseAttestableRequest(attestedTicket.getDerEncoding(), System.currentTimeMillis(), verifierDomain, new byte[0]);
    byte[] signature = SignatureUtility.signDeterministic(request.getSignable(), authenticatorKeys.getPrivate());
    request.setSignature(signature);
    return request;
  }

  private static AsymmetricCipherKeyPair loadKeys(String certDir, String privKeyDir) throws Exception {
    X509Certificate certificate = (X509Certificate) AuthenticatorLoader.loadCertificate(certDir);
    KeyPair javaKeys = AuthenticatorLoader.loadVerifiedKeyPair(certificate, privKeyDir);
    return SignatureUtility.JavaToBCKeys(javaKeys);
  }

}
