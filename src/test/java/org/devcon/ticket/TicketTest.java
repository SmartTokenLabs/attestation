package org.devcon.ticket;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

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

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    senderKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    otherKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

  @Test
  public void sunshine() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    assertEquals(TICKET_ID, ticket.getTicketId());
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
    
    List<byte[]> decoded = URLUtility.decodeList(ticket.getUrlEncoding());
    Ticket newTicket = (new TicketDecoder(senderKeys.getPublic())).decode(decoded.get(0));
    assertTrue(newTicket.verify());
    assertTrue(newTicket.checkValidity());
    assertArrayEquals(ticket.getDerEncoding(), newTicket.getDerEncoding());

    AsymmetricKeyParameter newIssuerPublicKey = SignatureUtility.restoreDefaultKey(decoded.get(1));
    Ticket otherConstructorTicket = new Ticket(newTicket.getDevconId(), newTicket.getTicketId(), newTicket.getTicketClass(),
        newTicket.getCommitment(), newTicket.getSignature(), newIssuerPublicKey);
    assertArrayEquals(ticket.getDerEncoding(), otherConstructorTicket.getDerEncoding());
  }

  @Test
  public void testTicketURLConsistentEncoding() throws IOException {
    BigInteger ticketID = new BigInteger("14840860468475837258758376");
    int ticketClass = 1; // VIP ticket
    BigInteger senderSecret = new BigInteger("186416");
    Ticket ticket = new Ticket("ticket@test.ts", "6", ticketID, ticketClass, senderKeys, senderSecret);
    String url = URLUtility.encodeData(ticket.getDerEncoding());
    Ticket newTicket =  (new TicketDecoder(senderKeys.getPublic())).decode(URLUtility.decodeData(url));
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

    Ticket newTicket = (new TicketDecoder(senderKeys.getPublic())).decode(encoded);
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
    encoded = ticket.getDerEncodingWithPK();
    Files.write(new File(PREFIX + "signed-devcon-ticket-with-pk.der").toPath(), encoded);
  }

  @Test
  public void testFullDecodingWithPK() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encoded = ticket.getDerEncodingWithPK();

    Ticket newTicket = (new TicketDecoder(senderKeys.getPublic())).decode(encoded);
    assertTrue(ticket.verify());
    assertTrue(newTicket.verify());
    assertArrayEquals(encoded, newTicket.getDerEncodingWithPK());

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

    assertArrayEquals(encoded, otherConstructor.getDerEncodingWithPK());

    Ticket noPKDecodingTicket = (new TicketDecoder()).decode(encoded);
    assertTrue(noPKDecodingTicket.verify());
    assertArrayEquals(encoded, noPKDecodingTicket.getDerEncodingWithPK());
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
  public void testWrongKey() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encoding = ticket.getDerEncodingWithPK();
    try {
      Ticket otherTicket = (new TicketDecoder(otherKeys.getPublic())).decode(encoding);
      fail();
    } catch (IllegalArgumentException e) {
      // Expected
    }
  }

  @Test
  public void testWrongKeyNoPKArgument() throws Exception {
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, senderKeys, SECRET);
    byte[] encoding = ticket.getDerEncoding();
    try {
      Ticket otherTicket = (new TicketDecoder(otherKeys.getPublic())).decode(encoding);
      fail();
    } catch (IllegalArgumentException e) {
      // Expected
    }
  }
}
