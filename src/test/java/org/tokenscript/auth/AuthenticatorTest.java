package org.tokenscript.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.Attestation;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.SignedAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.AttestationCryptoWithEthereumCharacteristics;
import com.alphawallet.attestation.core.SignatureUtility;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.devcon.ticket.Ticket;
import org.devcon.ticket.TicketDecoder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class AuthenticatorTest {
  static final byte[] failResponse = "fail".getBytes(StandardCharsets.UTF_8);
  private static final String verifyerDomain = "http://www.hotelbogota.com";
  private static final String issuerDomain = "http://www.hotelbogota.com";
  private static final ObjectMapper mapper = new ObjectMapper();
  private static AsymmetricCipherKeyPair authenticatorKeys, attestorKeys, ticketKeys;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;
  private static Authenticator authenticator;
  private static Verifier verifier;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCryptoWithEthereumCharacteristics(rand);
    authenticatorKeys = crypto.constructECKeys("secp384r1");
    attestorKeys = crypto.constructECKeys("secp256k1");
    ticketKeys = crypto.constructECKeys("secp256k1");
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    PublicKey javaAttestorPK = SignatureUtility.PublicBCKeyToJavaKey(attestorKeys.getPublic());
    KeyPair javaAuthenticatorKeys = SignatureUtility.BCKeysToJavaKey(authenticatorKeys);
    authenticator = new Authenticator(decoder, javaAttestorPK, issuerDomain, javaAuthenticatorKeys);
    verifier = new Verifier(verifyerDomain, javaAuthenticatorKeys.getPublic());
  }

  static UseAttestableRequest makeValidRequest() {
    BigInteger attestationSecret = new BigInteger("238469");
    String mail = "test@test.dk";
    int conferenceID = 6;
    BigInteger ticketID = new BigInteger("23544587786465");
    int ticketCLass = 0;
    Attestation att = HelperTest.makeUnsignedStandardAtt(authenticatorKeys.getPublic(), attestationSecret, mail);
    SignedAttestation signed = new SignedAttestation(att, attestorKeys);
    BigInteger ticketSecret = new BigInteger("6546584");
    Ticket ticket = new Ticket(mail, conferenceID, ticketID, ticketCLass, ticketKeys, ticketSecret);
    AttestedObject<Ticket> attestedTicket = new AttestedObject<Ticket>(ticket, signed,
        authenticatorKeys, attestationSecret, ticketSecret, crypto);
    UseAttestableRequest request = new UseAttestableRequest(attestedTicket.getDerEncoding(), System.currentTimeMillis(), verifyerDomain, new byte[0]);
    byte[] signature = SignatureUtility.signDeterministic(request.getSignable(), authenticatorKeys.getPrivate());
    request.setSignature(signature);
    return request;
  }

  @Test
  public void legalRequest() throws Exception {
    UseAttestableRequest request = makeValidRequest();
    byte[] requestBytes = mapper.writeValueAsBytes(request);
    byte[] jwtResponse = authenticator.validateRequest(requestBytes);
    assertTrue(verifier.verifyToken(jwtResponse));
  }

  @Test
  public void nullInput() {
    assertArrayEquals(authenticator.validateRequest(null), failResponse);
  }

  @Test
  public void notVerifiableInput() throws Exception {
    UseAttestableRequest request = new UseAttestableRequest(new byte[0], 0, verifyerDomain, new byte[0], new byte[0]);
    byte[] requestBytes = mapper.writeValueAsBytes(request);
    assertArrayEquals(authenticator.validateRequest(requestBytes), failResponse);
  }

  @Test
  public void wrongSignature() throws Exception {
    UseAttestableRequest request = makeValidRequest();
    AsymmetricCipherKeyPair newKeys = crypto.constructECKeys();
    byte[] signature = SignatureUtility.signDeterministic(request.getSignable(), newKeys.getPrivate());
    request.setSignature(signature);
    byte[] requestBytes = mapper.writeValueAsBytes(request);
    assertArrayEquals(authenticator.validateRequest(requestBytes), failResponse);
  }

  @Test
  public void tooOld() throws Exception {
    UseAttestableRequest request = makeValidRequest();
    request.setTimeStamp(request.getTimeStamp() - 2 * Authenticator.TIMELIMIT_IN_MS);
    byte[] requestBytes = mapper.writeValueAsBytes(request);
    assertArrayEquals(authenticator.validateRequest(requestBytes), failResponse);
  }

  @Test
  public void tooNew() throws Exception {
    UseAttestableRequest request = makeValidRequest();
    request.setTimeStamp(request.getTimeStamp() + 2 * Authenticator.TIMELIMIT_IN_MS);
    byte[] requestBytes = mapper.writeValueAsBytes(request);
    assertArrayEquals(authenticator.validateRequest(requestBytes), failResponse);
  }

}
