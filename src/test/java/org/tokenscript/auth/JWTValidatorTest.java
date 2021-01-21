package org.tokenscript.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.Attestation;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.SignedAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.AttestationCryptoWithEthereumCharacteristics;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.devcon.ticket.Ticket;
import org.devcon.ticket.TicketDecoder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class JWTValidatorTest {
  private static final String validatorDomain = "http://www.hotelbogota.com";

  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("546048445646851568430134455064804806");
  private static final int TICKET_CLASS = 0;  // Regular ticket
  private static final int CONFERENCE_ID = 6;
  private static final BigInteger TICKET_SECRET = new BigInteger("48646");
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");

  private static final ObjectMapper mapper = new ObjectMapper();
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
    userKeys = crypto.constructECKeys("secp384r1");
    attestorKeys = crypto.constructECKeys("secp256k1");
    ticketKeys = crypto.constructECKeys("secp256k1");
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
    //seems to work only whne there is no _ in the signature encoding
  }

  @Test
  public void wrongAttestedKey() throws Exception {
    AsymmetricCipherKeyPair newKeys = crypto.constructECKeys();
    AttestedObject attestedTicket = makeAttestedTicket();

    Field attestedKeys = SignedAttestation.class.getDeclaredField("attestationVerificationKey");
    attestedKeys.setAccessible(true);
    attestedKeys.set(attestedTicket.getAtt(), newKeys.getPublic());

    String token = issuer.makeToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void nullInput() {
    assertFalse(validator.validateRequest(null));
  }

//  @Test
//  public void wrongSignature() throws Exception {
//    UseAttestableRequest request = makeValidRequest();
//    AsymmetricCipherKeyPair newKeys = crypto.constructECKeys();
//    byte[] signature = SignatureUtility.signDeterministic(request.getSignable(), newKeys.getPrivate());
//    request.setSignature(signature);
//    byte[] requestBytes = mapper.writeValueAsBytes(request);
//    assertArrayEquals(validator.validateRequest(requestBytes), failResponse);
//  }
//
//  @Test
//  public void tooOld() throws Exception {
//    UseAttestableRequest request = makeValidRequest();
//    request.setTimeStamp(request.getTimeStamp() - 2 * validator.TIMELIMIT_IN_MS);
//    byte[] requestBytes = mapper.writeValueAsBytes(request);
//    assertArrayEquals(validator.validateRequest(requestBytes), failResponse);
//  }
//
//  @Test
//  public void tooNew() throws Exception {
//    UseAttestableRequest request = makeValidRequest();
//    request.setTimeStamp(request.getTimeStamp() + 2 * validator.TIMELIMIT_IN_MS);
//    byte[] requestBytes = mapper.writeValueAsBytes(request);
//    assertArrayEquals(validator.validateRequest(requestBytes), failResponse);
//  }

}
