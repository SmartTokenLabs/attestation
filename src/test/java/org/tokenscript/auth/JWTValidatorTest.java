package org.tokenscript.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.Attestation;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.SignedAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.AttestationCryptoWithEthereumCharacteristics;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.devcon.ticket.Ticket;
import org.devcon.ticket.TicketDecoder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class JWTValidatorTest {
  private static final String validatorDomain = "http://www.hotelbogota.com";

  private static final X9ECParameters SECP364R1 = SECNamedCurves.getByName("secp384r1");
  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("546048445646851568430134455064804806");
  private static final int TICKET_CLASS = 0;  // Regular ticket
  private static final int CONFERENCE_ID = 6;
  private static final BigInteger TICKET_SECRET = new BigInteger("48646");
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");

  private static AsymmetricCipherKeyPair userKeys, attestorKeys, ticketKeys;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;
  private static JWTValidator validator;
  private static JWTIssuer issuer;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCryptoWithEthereumCharacteristics(rand);
    userKeys = crypto.constructECKeys();
    attestorKeys = crypto.constructECKeys(SECP364R1);
    ticketKeys = crypto.constructECKeys(SECP364R1);
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    validator = new JWTValidator(decoder, attestorKeys.getPublic(), validatorDomain);
    issuer = new JWTIssuer(userKeys.getPrivate());
  }

  private static AttestedObject<Ticket> makeAttestedTicket() {
    Attestation att = HelperTest.makeUnsignedStandardAtt(userKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedAttestation signed = new SignedAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketKeys, TICKET_SECRET);
    AttestedObject attestedTicket = new AttestedObject<Ticket>(ticket, signed, userKeys, ATTESTATION_SECRET, TICKET_SECRET, crypto);
    assertTrue(attestedTicket.verify());
    assertTrue(attestedTicket.checkValidity());
    return attestedTicket;
  }

  @Test
  public void legalRequest() {
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = issuer.makeToken(attestedTicket, validatorDomain);
    assertTrue(validator.validateRequest(token));
  }

  @Test
  public void nullInput() {
    assertFalse(validator.validateRequest(null));
  }

  @Test
  public void wrongAttestedKey() {
    AsymmetricCipherKeyPair newKeys = crypto.constructECKeys();
    Attestation att = HelperTest.makeUnsignedStandardAtt(userKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedAttestation signed = new SignedAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketKeys, TICKET_SECRET);
    AttestedObject attestedTicket = new AttestedObject<Ticket>(ticket, signed, newKeys, ATTESTATION_SECRET, TICKET_SECRET, crypto);

    String token = issuer.makeToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void wrongSignature() {
    AsymmetricCipherKeyPair newKeys = crypto.constructECKeys();
    JWTIssuer newIssuer = new JWTIssuer(newKeys.getPrivate());
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = newIssuer.makeToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void tooOld() {
    AttestedObject attestedTicket = makeAttestedTicket();
    // Make token issued at currentTime minus limit
    long time = System.currentTimeMillis() - JWTCommon.TIMELIMIT_IN_MS - 10;
    String token = issuer.web3SignUnsignedJWT(issuer.buildUnsignedToken(attestedTicket, validatorDomain, time));
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void tooNew() {
    AttestedObject attestedTicket = makeAttestedTicket();
    // Make token issued at currentTime plus limit and some wiggle room for max time for the test to execute
    long time = System.currentTimeMillis() + JWTCommon.TIMELIMIT_IN_MS + 1000;
    String token = issuer.web3SignUnsignedJWT(issuer.buildUnsignedToken(attestedTicket, validatorDomain, time));
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void incorrectModifiedToken() {
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = issuer.makeToken(attestedTicket, validatorDomain);
    byte[] tokenBytes = token.getBytes(StandardCharsets.UTF_8);
    // Flip a bit
    tokenBytes[40] ^= 0x01;
    assertFalse(validator.validateRequest(new String(tokenBytes, StandardCharsets.UTF_8)));
  }

  @Test
  public void incorrectDomain() {
    AttestedObject attestedTicket = makeAttestedTicket();
    // Extra a in domain
    String token = issuer.makeToken(attestedTicket, "http://www.hotelbogotaa.com");
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void invalidDomainVerifier() {
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    assertThrows( RuntimeException.class, () -> {
      new JWTValidator(decoder, attestorKeys.getPublic(), "www.noHttpPrefix.com");
    });
  }

  @Test
  public void invalidDomainIssuer() {
    assertThrows( RuntimeException.class, () -> {
      JWTIssuer issuer = new JWTIssuer(userKeys.getPrivate());
      issuer.makeToken(null, "www.noHttpPrefix.com");
    });
  }

}
