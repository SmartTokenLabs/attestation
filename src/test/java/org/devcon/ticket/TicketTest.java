package org.devcon.ticket;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.URLUtility;


public class TicketTest {
  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("48646");
  private static final int TICKET_CLASS = 0; // Regular ticket
  private static final String CONFERENCE_ID = "6.Ø"; // Ensure it can handle utf8
  private static final BigInteger SECRET = new BigInteger("546048445646851568430134455064804806");

  private static AsymmetricCipherKeyPair senderKeys;
  private static AsymmetricCipherKeyPair otherKeys;
  private static SecureRandom rand;

  private static final String PREFIX = "build/test-results/";

  @BeforeEach
  public void init() {
    MockitoAnnotations.initMocks(this);
  }

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());
    senderKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    otherKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

  @Test
  public void sunshine() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    assertEquals(TICKET_ID, new BigInteger(ticket.getTicketId()));
    assertEquals(TICKET_CLASS, ticket.getTicketClass());
    assertEquals(CONFERENCE_ID, ticket.getDevconId());
    SubjectPublicKeyInfo ticketSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ticket.getPublicKey());
    SubjectPublicKeyInfo senderSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(senderKeys.getPublic());
    assertArrayEquals(senderSpki.getEncoded(), ticketSpki.getEncoded());
  }

  @Test
  public void testTicketURLSunshine() throws IOException  {
    BigInteger ticketID = new BigInteger("417541561854");
    int ticketClass = 0; // Regular Ticket
    BigInteger senderSecret = new BigInteger("45845870684");
    Ticket ticket = new Ticket("mah@mah.com", "6", ticketID, ticketClass, senderKeys, senderSecret);

    String ticketInUrl = new String(Base64.getUrlEncoder().encode(ticket.getDerEncoding()));

    FileWriter fileWriter = new FileWriter(PREFIX + "mah@mah.com.url");
    PrintWriter printWriter = new PrintWriter(fileWriter);
    printWriter.printf("%s?ticket=%s&secret=%s", Ticket.magicLinkURLPrefix, ticketInUrl, senderSecret.toString());
    // this should also work
    //printWriter.print(ticketInUrl);
    printWriter.close();

    String ticketUrl = Issuer.constructTicket("mah_v2@mah.com", "6", ticketID, ticketClass, Paths.get("src/test/data/namedEcPrivKey.pem"));
    FileWriter fileWriter2 = new FileWriter(PREFIX + "mah_v2@mah.com.url");
    PrintWriter printWriter2 = new PrintWriter(fileWriter2);
    printWriter2.print(ticketUrl);
    printWriter2.close();


    
    byte[] decoded = URLUtility.decodeData(ticket.getUrlEncoding());
    Ticket newTicket = (new DevconTicketDecoder(senderKeys.getPublic())).decode(decoded);
    assertTrue(newTicket.verify());
    assertTrue(newTicket.checkValidity());
    assertArrayEquals(ticket.getDerEncoding(), newTicket.getDerEncoding());

    Ticket otherConstructorTicket = new Ticket(newTicket.getDevconId(), newTicket.getTicketId(), newTicket.getTicketClass(),
        newTicket.getCommitment(), newTicket.getSignature(), senderKeys.getPublic());
    assertArrayEquals(ticket.getDerEncoding(), otherConstructorTicket.getDerEncoding());
  }

  @Test
  public void testTicketURLConsistentEncoding() throws IOException {
    BigInteger ticketID = new BigInteger("14840860468475837258758376");
    int ticketClass = 1; // VIP ticket
    BigInteger senderSecret = new BigInteger("186416");
    Ticket ticket = new Ticket("ticket@test.ts", "6", ticketID, ticketClass, senderKeys, senderSecret);
    String url = URLUtility.encodeData(ticket.getDerEncoding());
    Ticket newTicket =  (new DevconTicketDecoder(senderKeys.getPublic())).decode(URLUtility.decodeData(url));
    String newUrl = URLUtility.encodeData(newTicket.getDerEncoding());
    assertEquals(url, newUrl);
    /*** PRINT URL ***/
    System.out.println(url);
  }

  @Test
  public void testFullDecoding() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encoded = ticket.getDerEncoding();
    // write the ticket data
    Files.write(new File(PREFIX + "signed-devcon-ticket.der").toPath(), encoded);

    Ticket newTicket = (new DevconTicketDecoder(senderKeys.getPublic())).decode(encoded);
    assertTrue(ticket.verify());
    assertTrue(newTicket.verify());
    assertArrayEquals(encoded, newTicket.getDerEncoding());

    Ticket otherConstructor = new Ticket(newTicket.getDevconId(), newTicket.getTicketId(), newTicket.getTicketClass(),
        newTicket.getCommitment(), newTicket.getSignature(), newTicket.getPublicKey());
    assertEquals(ticket.getTicketId(), otherConstructor.getTicketId());
    assertEquals(ticket.getTicketClass(), otherConstructor.getTicketClass());
    assertEquals(ticket.getDevconId(), otherConstructor.getDevconId());
    assertEquals(ticket.getAlgorithm(), otherConstructor.getAlgorithm());
    assertArrayEquals(ticket.getCommitment(), otherConstructor.getCommitment());
    assertArrayEquals(ticket.getSignature(), otherConstructor.getSignature());
    SubjectPublicKeyInfo ticketSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ticket.getPublicKey());
    SubjectPublicKeyInfo otherSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(otherConstructor.getPublicKey());
    assertArrayEquals(ticketSpki.getEncoded(), otherSpki.getEncoded());

    assertArrayEquals(encoded, otherConstructor.getDerEncoding());
  }

  @Test
  public void saveDerEncoded() throws IOException {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encoded = ticket.getDerEncoding();
    // write the ticket data
    Files.write(new File(PREFIX + "signed-devcon-ticket.der").toPath(), encoded);
  }

  @Test
  public void stringTicketId() throws Exception {
    String ticketId = "some none integer ticket id";
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, ticketId, TICKET_CLASS, senderKeys, SECRET);
    assertEquals(ticketId, ticket.getTicketId());
    assertEquals(TICKET_CLASS, ticket.getTicketClass());
    assertEquals(CONFERENCE_ID, ticket.getDevconId());

    DevconTicketDecoder decoder = new DevconTicketDecoder(senderKeys.getPublic());
    Ticket newTicket = decoder.decode(ticket.getDerEncoding());
    assertTrue(newTicket.verify());
    assertTrue(newTicket.checkValidity());

    assertEquals(ticket.getTicketId(), newTicket.getTicketId());
    assertEquals(ticket.getTicketClass(), newTicket.getTicketClass());
    assertEquals(ticket.getDevconId(), newTicket.getDevconId());
    assertEquals(ticket.getAlgorithm(), newTicket.getAlgorithm());
    assertArrayEquals(ticket.getCommitment(), newTicket.getCommitment());
    assertArrayEquals(ticket.getSignature(), newTicket.getSignature());
    assertArrayEquals(ticket.getDerEncoding(), newTicket.getDerEncoding());
  }

  @Test
  public void testLegacyTicket() throws Exception {
    String legacyTicketUrl = "MIGXMFEMBDYuw5gCAwC-BgIBAARBBCtDxEZ1a0_c7qCE3k2UzDZQbziPc_mRgfdCGNi2wJx9GGM0Vg24wFNQX3s98rUVoJ8axKVcHlFAS0E2vFlSyZwDQgCc5Qp0GRCbBLQxw0C7K-pHmaDuuzaFwFO4tIVpjIAz0hNwZtshqRS_Z0R_rz2SbvQJeGcvy8ENnkFyyawubuiMHA==";
    byte[] legacyTicketBytes = URLUtility.decodeData(legacyTicketUrl);
    DevconTicketDecoder decoder = new DevconTicketDecoder(senderKeys.getPublic());
    Ticket legacyTicket = decoder.decode(legacyTicketBytes);
    assertTrue(legacyTicket.verify());
    assertTrue(legacyTicket.checkValidity());

    Ticket newTicket = decoder.decode(legacyTicketBytes);
    assertTrue(newTicket.verify());
    assertTrue(newTicket.checkValidity());

    assertEquals(legacyTicket.getTicketId(), newTicket.getTicketId());
    assertEquals(legacyTicket.getTicketClass(), newTicket.getTicketClass());
    assertEquals(legacyTicket.getDevconId(), newTicket.getDevconId());
    assertEquals(legacyTicket.getAlgorithm(), newTicket.getAlgorithm());
    assertArrayEquals(legacyTicket.getCommitment(), newTicket.getCommitment());
    assertArrayEquals(legacyTicket.getSignature(), newTicket.getSignature());
    assertArrayEquals(legacyTicketBytes, newTicket.getDerEncoding());
  }


  @Test
  public void testMultiplePks() throws Exception {
    Ticket firstTicket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] firstEncodedTicket = firstTicket.getDerEncoding();
    Ticket secondTicket = new Ticket(MAIL, "secondConference", TICKET_ID, TICKET_CLASS, otherKeys, SECRET);
    byte[] secondEncodedTicket = secondTicket.getDerEncoding();
    Map<String, AsymmetricKeyParameter> keys = new HashMap<>();
    keys.put(CONFERENCE_ID, senderKeys.getPublic());
    keys.put("secondConference", otherKeys.getPublic());
    AsymmetricCipherKeyPair yetAnotherKey = SignatureUtility.constructECKeysWithSmallestY(rand);
    keys.put("some conference", yetAnotherKey.getPublic());
    DevconTicketDecoder decoder = new DevconTicketDecoder(keys);
    Ticket restoredFirstTicket = decoder.decode(firstEncodedTicket);
    Ticket restoredSecondTicket = decoder.decode(secondEncodedTicket);
    assertTrue(restoredFirstTicket.verify());
    assertTrue(restoredFirstTicket.checkValidity());
    assertTrue(restoredSecondTicket.verify());
    assertTrue(restoredSecondTicket.checkValidity());
  }


  @Test
  public void testLisconTicketSunshine() throws Exception {
    LisconTicket ticket = new LisconTicket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    assertEquals(TICKET_ID, new BigInteger(ticket.getTicketId()));
    assertEquals(TICKET_CLASS, ticket.getTicketClass());
    assertEquals(CONFERENCE_ID, ticket.getDevconId());
    SubjectPublicKeyInfo ticketSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ticket.getPublicKey());
    SubjectPublicKeyInfo senderSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(senderKeys.getPublic());
    assertArrayEquals(senderSpki.getEncoded(), ticketSpki.getEncoded());
  }

  @Test
  public void testLisconTicketDecoder() throws Exception {
    String lisconTicket = "MIGWMA0MATYCBWE3ap3-AgEABEEEKJZVxMEXbkSZZBWnNUTX_5ieu8GUqf0bx_a0tBPF6QYskABaMJBYhDOXsmQt3csk_TfMZ2wdmfRkK7ePCOI2kgNCAOOZKRpcE6tLBuPbfE_SmwPk2wNjbj5vpa6kkD7eqQXvBOCa0WNo8dEHKvipeUGZZEWWjJKxooB44dEYdQO70Vgc";
    byte[] binaryLisconTicket = Base64.getUrlDecoder().decode(lisconTicket);
    // Normal ticket decoder is not compatible with Liscon ticket
    assertThrows(Exception.class, () -> new DevconTicketDecoder(senderKeys.getPublic()).decode(binaryLisconTicket));
    Ticket ticket = new LisconTicketDecoder(senderKeys.getPublic()).decode(binaryLisconTicket);
    assertTrue(ticket.verify());
    assertTrue(ticket.checkValidity());
  }

  @Test
  public void universalDecoderDevconTicket() throws Exception {
    Ticket devconTicket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    Map<String, AsymmetricKeyParameter> keys = new HashMap<>();
    keys.put(CONFERENCE_ID, senderKeys.getPublic());
    TicketDecoder decoder = new TicketDecoder(keys);
    Ticket decodedTicket = decoder.decode(devconTicket.getDerEncoding());
    assertArrayEquals(devconTicket.getDerEncoding(), decodedTicket.getDerEncoding());
    assertTrue(decodedTicket.checkValidity());
    assertTrue(decodedTicket.verify());
  }

  @Test
  public void universalDecoderLisconTicket() throws Exception {
    Ticket lisconTicket = new LisconTicket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    TicketDecoder decoder = new TicketDecoder(senderKeys.getPublic());
    Ticket decodedTicket = decoder.decode(lisconTicket.getDerEncoding());
    assertArrayEquals(lisconTicket.getDerEncoding(), decodedTicket.getDerEncoding());
    assertTrue(decodedTicket.checkValidity());
    assertTrue(decodedTicket.verify());
  }

  @Test
  public void universalDecoderInvalidTicket() throws Exception {
    TicketDecoder decoder = new TicketDecoder(senderKeys.getPublic());
    Exception e = assertThrows(RuntimeException.class, ()-> decoder.decode(new byte[] {0x00}));
    assertEquals(e.getMessage(), "Could not decode ticket");
  }

  @Test
  public void testMissingKey() {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encodedTicket = ticket.getDerEncoding();
    DevconTicketDecoder decoder = new DevconTicketDecoder();
    assertThrows(RuntimeException.class, ()-> decoder.decode(encodedTicket));
  }

  @Test
  public void testWrongPkNames()  {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encodedTicket = ticket.getDerEncoding();
    Map<String, AsymmetricKeyParameter> keys = new HashMap<>();
    // Incorrect conference name
    keys.put("incorrect conference", senderKeys.getPublic());
    keys.put("secondConference", otherKeys.getPublic());
    DevconTicketDecoder decoder = new DevconTicketDecoder(keys);
    Exception e = assertThrows(IllegalArgumentException.class, ()-> decoder.decode(encodedTicket));
    assertEquals("Conference ID " + CONFERENCE_ID + ", does not match any associated PK", e.getMessage());
  }

  @Test
  public void conferenceCannotBeCalledDefault() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encodedTicket = ticket.getDerEncoding();
    Map<String, AsymmetricKeyParameter> keys = new HashMap<>();
    // NOTICE that we are explicitly calling the key default, but if key names are included the correct devconID MUST be used
    keys.put("default", senderKeys.getPublic());
    Exception e = assertThrows(IllegalArgumentException.class, ()-> new DevconTicketDecoder(keys));
    assertEquals("A conference cannot be called default", e.getMessage());
  }

  @Test
  public void testWrongUserSuppliedKey() {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, otherKeys, SECRET);
    byte[] encoding = ticket.getDerEncoding();
    DevconTicketDecoder decoder = new DevconTicketDecoder(senderKeys.getPublic());
    // The constructor verification will fail
    assertThrows(IllegalArgumentException.class, ()-> decoder.decode(encoding));
  }
  @Test
  public void testIllegalKeys() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    Field field = ticket.getClass().getDeclaredField("signature");
    field.setAccessible(true);
    // Change a bit in the signature
    ((byte[]) field.get(ticket))[20] ^= 1;
    assertFalse(ticket.verify());
    // Check we cannot make a new ticket with invalid signature
    try {
      Ticket newTicket = new Ticket(ticket.getDevconId(), ticket.getTicketId(), ticket.getTicketClass(),
          ticket.getCommitment(), ticket.getSignature(),
          senderKeys.getPublic());
      fail();
    } catch (IllegalArgumentException e) {
      // Expected
    }
  }

  @Test
  public void testWrongKeyLiscon() throws Exception {
    Ticket ticket = new LisconTicket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encoding = ticket.getDerEncoding();
    assertThrows(RuntimeException.class, ()-> new LisconTicketDecoder(otherKeys.getPublic()).decode(encoding));
  }

  @Test
  public void testWrongPksMaps()  {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encodedTicket = ticket.getDerEncoding();
    Map<String, AsymmetricKeyParameter> keys = new HashMap<>();
    // Incorrect conference name
    keys.put("incorrect conference", senderKeys.getPublic());
    // Correct conference name, but wrong key
    keys.put(CONFERENCE_ID, otherKeys.getPublic());
    DevconTicketDecoder decoder = new DevconTicketDecoder(keys);
    Exception e = assertThrows(IllegalArgumentException.class, ()-> decoder.decode(encodedTicket));
    assertEquals("Signature is invalid", e.getMessage());
  }

  // Validates fix of https://github.com/TokenScript/attestation/issues/192
  @Test
  public void wrongCommitment() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    assertTrue(ticket.checkValidity());
    assertTrue(ticket.verify());
    byte[] commitmentWrongEmail = AttestationCrypto.makeCommitment("wrong@mail.dk", AttestationType.EMAIL, SECRET);
    Field field = ticket.getClass().getDeclaredField("commitment");
    field.setAccessible(true);
    // Should make signature fail
    field.set(ticket, commitmentWrongEmail);
    assertTrue(ticket.checkValidity());
    assertFalse(ticket.verify());
  }
}
