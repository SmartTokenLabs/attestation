package org.devcon.ticket;

import com.alphawallet.ethereum.TicketAttestationReturn;
import com.alphawallet.token.tools.Numeric;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.*;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.DERUtility;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.demo.SmartContract;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

public class UseTicketTest {
  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("546048445646851568430134455064804806");
  private static final int TICKET_CLASS = 0;  // Regular ticket
  private static final String CONFERENCE_ID = "Åø"; // Ensure non-number non ASCII can be handled
  private static final BigInteger TICKET_SECRET = new BigInteger("48646");
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");
  private static final byte[] UN = new byte[] { 0x42 };

  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair attestorKeys;
  private static AsymmetricCipherKeyPair ticketIssuerKeys;
  private static AsymmetricCipherKeyPair fakeSupplimentalKey;
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
    fakeSupplimentalKey = SignatureUtility.constructECKeys(rand);

    System.out.println("subject: " + SignatureUtility.addressFromKey(subjectKeys.getPublic()));
    System.out.println("attestor: " + SignatureUtility.addressFromKey(attestorKeys.getPublic()));
    System.out.println("ticketIssuer: " + SignatureUtility.addressFromKey(ticketIssuerKeys.getPublic()));
  }

  @BeforeEach
  public void makeAttestedTicket() {
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    attestedTicket = new AttestedObject<>(ticket, signed, ATTESTATION_SECRET, TICKET_SECRET, UN, crypto);
    assertTrue(attestedTicket.verify());
    assertTrue(attestedTicket.checkValidity());
  }

  // Write test material to be used in JS testing
  @Test
  void writeTestMaterial() throws Exception {
    FileImportExport.storeKey(ticketIssuerKeys.getPublic(), "ticket-issuer-key");
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    FileImportExport.storeMaterial(ticket, "ticket");
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    FileImportExport.storeKey(attestorKeys.getPublic(), "att-issuer-key");
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    FileImportExport.storeMaterial(signed, "signed-att");
    AttestedObject<Ticket> attestedTicket = new AttestedObject<>(ticket, signed, ATTESTATION_SECRET, TICKET_SECRET, UN, crypto);
    FileImportExport.storeMaterial(attestedTicket, "attested-ticket");

    // Validate loading
    AsymmetricKeyParameter ticketValidationKey = FileImportExport.loadKey("ticket-issuer-key");

    DevconTicketDecoder ticketDecoder = new DevconTicketDecoder(ticketValidationKey);
    Ticket decodedTicket = FileImportExport.loadMaterial(ticketDecoder, "ticket");
    assertTrue(decodedTicket.verify());
    assertTrue(decodedTicket.checkValidity());

    AsymmetricKeyParameter attValidationKey = FileImportExport.loadKey("att-issuer-key");
    Function<byte[], SignedIdentifierAttestation> attDec = (input) -> {
      try {
        return new SignedIdentifierAttestation(input, attValidationKey);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    };
    SignedIdentifierAttestation decodedAtt = FileImportExport.loadMaterial(attDec, "signed-att");
    assertTrue(decodedAtt.verify());
    assertTrue(decodedAtt.checkValidity());

    AttestedObjectDecoder<Ticket> attestedTicketDecoder = new AttestedObjectDecoder<>(ticketDecoder, attValidationKey);
    AttestedObject<Ticket> decodedAttestedTicket = FileImportExport.loadMaterial(attestedTicketDecoder, "attested-ticket");
    assertTrue(decodedAttestedTicket.verify());
    assertTrue(decodedAttestedTicket.checkValidity());
  }

  @Test
  void testSunshine() {
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
  void testWithUnpredictableNumberBundle() {
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    UnpredictableNumberTool unt = new UnpredictableNumberTool(rand, new byte[]{0x01, 0x02}, "http://www.domain.com");
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    AttestedObject<Ticket> attestedTicket = new AttestedObject<>(ticket, signed,
            ATTESTATION_SECRET, TICKET_SECRET, un.getNumber().getBytes(), crypto);
    assertTrue(attestedTicket.verify());
    assertTrue(attestedTicket.checkValidity());
    // Validate the UN is correct
    assertTrue(unt.validateUnpredictableNumber(un.getNumber(), un.getRandomness(), un.getExpiration()));
    assertArrayEquals(attestedTicket.getPok().getUnpredictableNumber(), un.getNumber().getBytes());
  }

  @Test
  void testDecoding() throws InvalidObjectException {
    AttestedObject<Ticket> newAttestedTicket = new AttestedObject<>(attestedTicket.getDerEncoding(), new DevconTicketDecoder(
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
    assertEquals(SignatureUtility.addressFromKey(attestedTicket.getAttestedUserKey()),
            SignatureUtility.addressFromKey(subjectKeys.getPublic()));
    assertArrayEquals(attestedTicket.getDerEncoding(), newAttestedTicket.getDerEncoding());

    AttestedObject<Ticket> newConstructor = new AttestedObject<>(attestedTicket.getAttestableObject(),
            attestedTicket.getAtt(), attestedTicket.getPok());

    assertArrayEquals(newConstructor.getDerEncoding(), attestedTicket.getDerEncoding());
  }

  @Test
  void testSmartContractDecode() throws Exception {
    //try building all components
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL, 15); //valid for 15 seconds
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    AttestedObject<Ticket> useTicket = new AttestedObject<>(ticket, signed, ATTESTATION_SECRET, TICKET_SECRET, UN, crypto);

    //now attempt to dump data from contract:
    TicketAttestationReturn tar = contract.callVerifyTicketAttestation(useTicket.getDerEncoding());

    System.out.println("Call SmartContract to check Ticket");

    //check returned values
    assertTrue(tar.subjectAddress.equalsIgnoreCase(SignatureUtility.addressFromKey(subjectKeys.getPublic())));
    assertTrue(tar.issuerAddress.equalsIgnoreCase(SignatureUtility.addressFromKey(ticketIssuerKeys.getPublic())));
    assertTrue(tar.attestorAddress.equalsIgnoreCase(SignatureUtility.addressFromKey(attestorKeys.getPublic())));
    assertTrue(tar.attestationValid);
    assertEquals(TICKET_ID, Numeric.toBigInt(tar.ticketId));

    System.out.println("Test passed");
    System.out.println("Creating an attestation which only just expired ...");

    att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL, -19); //expires instantly
    signed = new SignedIdentifierAttestation(att, attestorKeys);
    ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    // TODO this lines causes sporadic failures with issues in the asn1 encoding.
    useTicket = new AttestedObject<>(ticket, signed, ATTESTATION_SECRET, TICKET_SECRET, UN, crypto);

    tar = contract.callVerifyTicketAttestation(useTicket.getDerEncoding());
    assertFalse(tar.attestationValid);
    assertArrayEquals(new byte[0], tar.ticketId);
    assertEquals("0x0000000000000000000000000000000000000000", tar.subjectAddress);
    assertEquals("0x0000000000000000000000000000000000000000", tar.attestorAddress);
    assertEquals("0x0000000000000000000000000000000000000000", tar.issuerAddress);
    System.out.println("Ticket now invalid");

    //Now run a test without the blockchain friendly timestamp
    System.out.println("Creating a non blockchain friendly attestation");
    att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL); //valid for 15 seconds
    signed = new SignedIdentifierAttestation(att, attestorKeys, false);
    ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    useTicket = new AttestedObject<>(ticket, signed, ATTESTATION_SECRET, TICKET_SECRET, UN, crypto);

    //test should fail
    tar = contract.callVerifyTicketAttestation(useTicket.getDerEncoding());
    assertFalse(tar.attestationValid);
    assertArrayEquals(new byte[0], tar.ticketId);
    assertEquals("0x0000000000000000000000000000000000000000", tar.subjectAddress);
    assertEquals("0x0000000000000000000000000000000000000000", tar.attestorAddress);
    assertEquals("0x0000000000000000000000000000000000000000", tar.issuerAddress);
    System.out.println("Ticket now invalid");

    System.out.println("Test with wrong ticket issuer key");
    //Now test with wrong ticket issuer key
    att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    signed = new SignedIdentifierAttestation(att, attestorKeys);
    ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, fakeSupplimentalKey, TICKET_SECRET);
    useTicket = new AttestedObject<>(ticket, signed, ATTESTATION_SECRET, TICKET_SECRET, UN, crypto);

    tar = contract.callVerifyTicketAttestation(useTicket.getDerEncoding(), SignatureUtility.addressFromKey(attestorKeys.getPublic()), SignatureUtility.addressFromKey(ticketIssuerKeys.getPublic()));
    assertFalse(tar.attestationValid);
    assertArrayEquals(new byte[0], tar.ticketId);
    assertEquals("0x0000000000000000000000000000000000000000", tar.subjectAddress);
    assertEquals("0x0000000000000000000000000000000000000000", tar.attestorAddress);
    assertEquals("0x0000000000000000000000000000000000000000", tar.issuerAddress);
    System.out.println("Ticket now invalid");

    System.out.println("Test with incorrect attestation issuer key passed");
    att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    signed = new SignedIdentifierAttestation(att, fakeSupplimentalKey);
    ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    useTicket = new AttestedObject<>(ticket, signed, ATTESTATION_SECRET, TICKET_SECRET, UN, crypto);

    tar = contract.callVerifyTicketAttestation(useTicket.getDerEncoding(), SignatureUtility.addressFromKey(attestorKeys.getPublic()), SignatureUtility.addressFromKey(ticketIssuerKeys.getPublic()));
    assertFalse(tar.attestationValid);
    assertArrayEquals(new byte[0], tar.ticketId);
    assertEquals("0x0000000000000000000000000000000000000000", tar.subjectAddress);
    assertEquals("0x0000000000000000000000000000000000000000", tar.attestorAddress);
    assertEquals("0x0000000000000000000000000000000000000000", tar.issuerAddress);
    System.out.println("Ticket now invalid");

    System.out.println("Test with incorrect issuer key passed");
  }

  @Test
  void testRebuildComponents() {
    //try building all components
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
    AttestedObject<Ticket> useTicket = new AttestedObject<>(ticket, signed, ATTESTATION_SECRET, TICKET_SECRET, UN, crypto);

    AttestedObject<Ticket> newUseTicket = new AttestedObject<>(useTicket.getDerEncoding(), new DevconTicketDecoder(
            ticketIssuerKeys.getPublic()), attestorKeys.getPublic());

    assertTrue(newUseTicket.getAttestableObject().verify());
    assertTrue(newUseTicket.getAtt().verify());
    assertTrue(newUseTicket.verify());
    assertTrue(newUseTicket.checkValidity());

    AttestedObject<Ticket> newConstructor = new AttestedObject<>(this.attestedTicket.getAttestableObject(),
            this.attestedTicket.getAtt(), this.attestedTicket.getPok());

    assertArrayEquals(newConstructor.getDerEncoding(), this.attestedTicket.getDerEncoding());
    assertTrue(newConstructor.getAttestableObject().verify());
    assertTrue(newConstructor.getAtt().verify());
    assertTrue(newConstructor.verify());
    assertTrue(newConstructor.checkValidity());
  }

  @Test
  void testNegativeAttestation() throws Exception {
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
  void testNegativeUnmatchingKeys() throws Exception {
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
  void testNegativeDifferentKeys() throws Exception {
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
  void testNegativeWrongProofIdentifier() throws Exception {
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
  void testNegativeWrongRiddle() throws Exception {
    Ticket newTicket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, subjectKeys, TICKET_SECRET);
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
  void testNegativeConstruction() {
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    // Add an extra t in the mail
    Ticket ticket = new Ticket("testt@test.ts", CONFERENCE_ID, TICKET_ID, TICKET_CLASS, subjectKeys, TICKET_SECRET);
    try {
      AttestedObject<Ticket> current = new AttestedObject<>(ticket, signed, ATTESTATION_SECRET,
              TICKET_SECRET, UN, crypto);
      fail();
    } catch (RuntimeException e) {
      // Expected not to be able to construct a proof for a wrong email
    }
  }

  @Test
  void testNegativeConstruction2() {
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, subjectKeys, TICKET_SECRET);
    // Expected not to be able to construct a proof for a wrong secret
    assertThrows(RuntimeException.class, () -> new AttestedObject<>(ticket, signed,
            TICKET_SECRET.add(BigInteger.ONE), ATTESTATION_SECRET, UN, crypto));
    // Expected not to be able to construct a proof for a wrong secret
    assertThrows(RuntimeException.class, () -> new AttestedObject<>(ticket, signed, TICKET_SECRET,
            ATTESTATION_SECRET.add(BigInteger.ONE), UN, crypto));
    // Expected not to be able to construct a proof for a wrong secret
    assertThrows(RuntimeException.class, () -> new AttestedObject<>(ticket, signed,
            TICKET_SECRET.add(BigInteger.ONE), ATTESTATION_SECRET.add(BigInteger.ONE), UN, crypto));
  }
}
