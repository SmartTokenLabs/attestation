package org.devcon.ticket;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.IdentifierAttestation;
import com.alphawallet.attestation.SignedIdentityAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class UseTicketBundleTest {
  private static final String DOMAIN = "http://www.hotel-bogota.com";
  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("546048445646851568430134455064804806");
  private static final int TICKET_CLASS = 0;  // Regular ticket
  private static final String CONFERENCE_ID = "Åø"; // Ensure non-number non ASCII can be handled
  private static final BigInteger TICKET_SECRET = new BigInteger("48646");
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");

  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair attestorKeys;
  private static AsymmetricCipherKeyPair ticketIssuerKeys;
  private static byte[] macKey;
  private static UnpredictibleNumberTool unt;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;
  private AttestedObject<Ticket> attestedTicket;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    crypto = new AttestationCrypto(rand);
    subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    attestorKeys = SignatureUtility.constructECKeys(rand);
    ticketIssuerKeys = SignatureUtility.constructECKeys(rand);
    macKey = rand.generateSeed(16);
    unt = new UnpredictibleNumberTool(macKey, DOMAIN, UnpredictibleNumberTool.DEFAULT_VALIDITY_IN_MS);
  }

  @BeforeEach
  public void makeAttestedTicket() {
    IdentifierAttestation att = HelperTest
        .makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedIdentityAttestation signed = new SignedIdentityAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    attestedTicket = new AttestedObject<Ticket>(ticket, signed, subjectKeys, ATTESTATION_SECRET, TICKET_SECRET, crypto);
  }

  @Test
  public void sunshine() throws Exception {
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    UseTicketBundle bundle = new UseTicketBundle(attestedTicket, un, subjectKeys.getPrivate());
    assertTrue(bundle.verify());
    assertTrue(bundle.validateAndVerify(unt));
  }

  @Test
  public void testDeEncoding1() throws Exception {
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    UseTicketBundle bundle = new UseTicketBundle(attestedTicket, un, subjectKeys.getPrivate());
    String refJson = bundle.getJsonBundle();
    UseTicketBundle newBundle = new UseTicketBundle(refJson, ticketIssuerKeys.getPublic(), attestorKeys.getPublic());
    assertTrue(newBundle.verify());
    assertTrue(newBundle.validateAndVerify(unt));
    assertEquals(refJson, newBundle.getJsonBundle());
  }

  @Test
  public void testDeEncoding2() throws Exception {
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    UseTicketBundle bundle = new UseTicketBundle(attestedTicket, un, subjectKeys.getPrivate());
    String refJson = bundle.getJsonBundle();
    UseTicketBundle newBundle = new UseTicketBundle(bundle.getUseTicket(), bundle.getUn(), bundle.getSignature());
    assertTrue(newBundle.verify());
    assertTrue(newBundle.validateAndVerify(unt));
    assertEquals(refJson, newBundle.getJsonBundle());
  }
}
