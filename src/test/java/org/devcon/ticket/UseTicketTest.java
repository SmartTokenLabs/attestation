package org.devcon.ticket;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.alphawallet.attestation.Attestation;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.IdentifierAttestation;
import com.alphawallet.attestation.ProofOfExponent;
import com.alphawallet.attestation.SignedIdentifierAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.DERUtility;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.demo.SmartContract;
import com.alphawallet.ethereum.TicketAttestationReturn;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class UseTicketTest {
  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("546048445646851568430134455064804806");
  private static final int TICKET_CLASS = 0;  // Regular ticket
  private static final String CONFERENCE_ID = "Åø"; // Ensure non-number non ASCII can be handled
  private static final BigInteger TICKET_SECRET = new BigInteger("48646");
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");

  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair attestorKeys;
  private static AsymmetricCipherKeyPair ticketIssuerKeys;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;
  private AttestedObject<Ticket> attestedTicket;
  private final SmartContract contract = new SmartContract();

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());

    crypto = new AttestationCrypto(rand);
    subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    attestorKeys = SignatureUtility.constructECKeys(rand);
    ticketIssuerKeys = SignatureUtility.constructECKeys(rand);

    System.out.println("subject: " + SignatureUtility.addressFromKey(subjectKeys.getPublic()));
    System.out.println("attestor: " + SignatureUtility.addressFromKey(attestorKeys.getPublic()));
    System.out.println("ticketIssuer: " + SignatureUtility.addressFromKey(ticketIssuerKeys.getPublic()));
  }

  @BeforeEach
  public void makeAttestedTicket() {
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    attestedTicket = new AttestedObject<Ticket>(ticket, signed, subjectKeys.getPublic(), ATTESTATION_SECRET, TICKET_SECRET, crypto);
    assertTrue(attestedTicket.verify());
    assertTrue(attestedTicket.checkValidity());
  }

  @Test
  public void testSunshine() {
    // *** PRINT DER ENCODING OF OBJECTS ***
    try {
      PublicKey pk;
      System.out.println("Signed attestation:");
      DERUtility.writePEM(attestedTicket.getAtt().getDerEncoding(), "SIGNABLE", System.out);
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(attestorKeys.getPublic()));
      System.out.println("Attestation verification key:");
      DERUtility.writePEM(pk.getEncoded(), "PUBLIC KEY", System.out);

      System.out.println("Ticket:");
      DERUtility.writePEM(attestedTicket.getAttestableObject().getDerEncoding(), "TICKET", System.out);
      System.out.println("Signed ticket verification key:");
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ticketIssuerKeys.getPublic()));
      DERUtility.writePEM(pk.getEncoded(), "PUBLIC KEY", System.out);

      System.out.println("Attested Ticket:");
      DERUtility.writePEM(attestedTicket.getDerEncoding(), "ATTESTED-TICKET", System.out);
      System.out.println("Signed user public key (for verification of attested ticket):");
      pk = new EC().generatePublic(
          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(subjectKeys.getPublic()));
      DERUtility.writePEM(pk.getEncoded(), "PUBLIC KEY", System.out);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void testDecoding() throws InvalidObjectException {
    AttestedObject newAttestedTicket = new AttestedObject(attestedTicket.getDerEncoding(), new TicketDecoder(
        ticketIssuerKeys.getPublic()), attestorKeys.getPublic());
    assertTrue(newAttestedTicket.getAttestableObject().verify());
    assertTrue(newAttestedTicket.verify());
    assertTrue(newAttestedTicket.checkValidity());
    assertTrue(newAttestedTicket.getAtt().verify());
    assertTrue(AttestationCrypto.verifyEqualityProof(newAttestedTicket.getAtt().getUnsignedAttestation().getCommitment(), newAttestedTicket.getAttestableObject().getCommitment(), newAttestedTicket.getPok()));

    assertArrayEquals(attestedTicket.getAttestableObject().getDerEncoding(),
        newAttestedTicket.getAttestableObject().getDerEncoding());
    assertArrayEquals(attestedTicket.getAtt().getDerEncoding(), newAttestedTicket.getAtt().getDerEncoding());
    assertArrayEquals(attestedTicket.getPok().getDerEncoding(), newAttestedTicket.getPok().getDerEncoding());
    assertEquals(attestedTicket.getUserPublicKey(), subjectKeys.getPublic());
    assertArrayEquals(attestedTicket.getDerEncoding(), newAttestedTicket.getDerEncoding());

    AttestedObject newConstructor = new AttestedObject(attestedTicket.getAttestableObject(),
        attestedTicket.getAtt(), attestedTicket.getPok());

    assertArrayEquals(newConstructor.getDerEncoding(), attestedTicket.getDerEncoding());
  }

  @Test
  public void testSmartContractDecode() throws Exception {
    //try building all components
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    AttestedObject<Ticket> useTicket = new AttestedObject<>(ticket, signed, subjectKeys.getPublic(), ATTESTATION_SECRET, TICKET_SECRET, crypto);

    // TODO @James I have changed this test to compile and not use the signature
    //now attempt to dump data from contract:
    TicketAttestationReturn tar = contract.callVerifyTicketAttestation(useTicket.getDerEncoding());

    //check returned values
    assertTrue(tar.subjectAddress.equalsIgnoreCase(SignatureUtility.addressFromKey(subjectKeys.getPublic())));
    assertTrue(tar.issuerAddress.equalsIgnoreCase(SignatureUtility.addressFromKey(ticketIssuerKeys.getPublic())));
    assertTrue(tar.attestorAddress.equalsIgnoreCase(SignatureUtility.addressFromKey(attestorKeys.getPublic())));
  }

  @Test
  public void testRebuildComponents() throws InvalidObjectException {
    //try building all components
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    AttestedObject<Ticket> useTicket = new AttestedObject<>(ticket, signed, subjectKeys.getPublic(), ATTESTATION_SECRET, TICKET_SECRET, crypto);

    AttestedObject<Ticket> newUseTicket = new AttestedObject<Ticket>(useTicket.getDerEncoding(), new TicketDecoder(
            ticketIssuerKeys.getPublic()), attestorKeys.getPublic());

    assertTrue(newUseTicket.getAttestableObject().verify());
    assertTrue(newUseTicket.getAtt().verify());
    assertTrue(newUseTicket.verify());
    assertTrue(newUseTicket.checkValidity());

    AttestedObject newConstructor = new AttestedObject(this.attestedTicket.getAttestableObject(),
            this.attestedTicket.getAtt(), this.attestedTicket.getPok());

    assertArrayEquals(newConstructor.getDerEncoding(), this.attestedTicket.getDerEncoding());
    assertTrue(newConstructor.getAttestableObject().verify());
    assertTrue(newConstructor.getAtt().verify());
    assertTrue(newConstructor.verify());
    assertTrue(newConstructor.checkValidity());
  }

  @Test
  public void testNegativeAttestation() throws Exception {
    Attestation att = attestedTicket.getAtt().getUnsignedAttestation();
    Field field = att.getClass().getSuperclass().getDeclaredField("version");
    field.setAccessible(true);
    // Invalid version for Identifier Attestation along with failing signature
    field.set(att, new ASN1Integer(19));
    // Only correctly formed Identifier Attestations are allowed
    assertFalse(att.checkValidity());
    assertFalse(attestedTicket.checkValidity());
    // Verification should also fail since signature is now invalid
    assertFalse(attestedTicket.getAtt().verify());
    assertFalse(attestedTicket.verify());
  }

  // Test that the key used to sign the Attested Ticket is the same as attested to
  @Test
  public void testNegativeUnmatchingKeys() throws Exception {
    Attestation att = attestedTicket.getAtt().getUnsignedAttestation();
    Field field = att.getClass().getSuperclass().getDeclaredField("subjectPublicKeyInfo");
    field.setAccessible(true);
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory
        .createSubjectPublicKeyInfo(attestorKeys.getPublic());
    assertFalse(Arrays.equals(spki.getEncoded(), att.getSubjectPublicKeyInfo().getEncoded()));
    // Change public key
    field.set(att, spki);
    // Validation of attestation should not fail
    assertTrue(attestedTicket.getAtt().checkValidity());
    // But validation of ticket should since the keys used are not consistent
    assertFalse(attestedTicket.checkValidity());
    // Verification should fail
    assertFalse(attestedTicket.getAtt().verify());
    assertFalse(attestedTicket.verify());
  }

  @Test
  public void testNegativeDifferentKeys() throws Exception {
    SignedIdentifierAttestation att = attestedTicket.getAtt();
    Field field = att.getClass().getDeclaredField("attestationVerificationKey");
    field.setAccessible(true);
    // Change public key
    field.set(att, subjectKeys.getPublic());
    // Verification should fail
    assertFalse(att.verify());
    assertFalse(attestedTicket.verify());
  }

  @Test
  public void testNegativeWrongProofIdentifier() throws Exception {
    // Wrong attestation secret
    ProofOfExponent newPok = crypto
        .computeEqualityProof(attestedTicket.getAtt().getUnsignedAttestation().getCommitment(), attestedTicket.getAttestableObject().getCommitment(), new BigInteger("42424242"), TICKET_SECRET);
    Field field = attestedTicket.getClass().getDeclaredField("pok");
    field.setAccessible(true);
    // Change the proof
    field.set(attestedTicket, newPok);
    // Validation should still pass
    assertTrue(attestedTicket.checkValidity());
    // Verification of the proof itself should fail
    assertFalse(AttestationCrypto.verifyEqualityProof(attestedTicket.getAtt().getUnsignedAttestation().getCommitment(), attestedTicket.getAttestableObject().getCommitment(), newPok));
    // Verification should fail of the attested ticket
    assertFalse(attestedTicket.verify());
  }

  @Test
  public void testNegativeWrongRiddle() throws Exception {
    Ticket newTicket  = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, subjectKeys, TICKET_SECRET);
    assertTrue(newTicket.checkValidity());
    assertTrue(newTicket.verify());
    Field field = attestedTicket.getClass().getDeclaredField("attestableObject");
    field.setAccessible(true);
    // Set new ticket
    field.set(attestedTicket, newTicket);
    // Validation should still pass since tickets on their own are always valid
    assertTrue(attestedTicket.checkValidity());
    // Verification should not fail
    assertTrue(attestedTicket.verify());
  }

  @Test
  public void testNegativeConstruction() {
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    // Add an extra t in the mail
    Ticket ticket = new Ticket("testt@test.ts", CONFERENCE_ID, TICKET_ID, TICKET_CLASS, subjectKeys, TICKET_SECRET);
    try {
      AttestedObject current = new AttestedObject(ticket, signed, subjectKeys.getPublic(), ATTESTATION_SECRET,
          TICKET_SECRET, crypto);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong email
    }
  }

  @Test
  public void testNegativeConstruction2() {
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, subjectKeys, TICKET_SECRET);
    try {
      // Wrong subject secret
      AttestedObject current = new AttestedObject(ticket, signed, subjectKeys.getPublic(),
          TICKET_SECRET.add(BigInteger.ONE), ATTESTATION_SECRET, crypto);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong secret
    }
    try {
      // Wrong attestation secret
      AttestedObject current = new AttestedObject(ticket, signed, subjectKeys.getPublic(), TICKET_SECRET,
          ATTESTATION_SECRET.add(BigInteger.ONE), crypto);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong secret
    }
    try {
      // Correlated secrets
      AttestedObject current = new AttestedObject(ticket, signed, subjectKeys.getPublic(),
          TICKET_SECRET.add(BigInteger.ONE), ATTESTATION_SECRET.add(BigInteger.ONE), crypto);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong secret
    }
  }

  @Test
  public void testNonAttestedSigningKey() {
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    AsymmetricCipherKeyPair newKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    attestedTicket = new AttestedObject<Ticket>(ticket, signed, newKeys.getPublic(), ATTESTATION_SECRET, TICKET_SECRET, crypto);
    assertTrue(attestedTicket.verify());
    assertFalse(attestedTicket.checkValidity());
  }
}
