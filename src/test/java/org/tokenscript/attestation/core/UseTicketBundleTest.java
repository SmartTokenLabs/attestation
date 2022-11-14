package org.tokenscript.attestation.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.stream.Stream;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.devcon.ticket.Ticket;
import org.devcon.ticket.UseTicketBundle;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.tokenscript.attestation.AttestedObject;
import org.tokenscript.attestation.HelperTest;
import org.tokenscript.attestation.IdentifierAttestation;
import org.tokenscript.attestation.SignedIdentifierAttestation;

public class UseTicketBundleTest {
  private static final String DOMAIN = "http://www.hotel-bogota.com";
  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("546048445646851568430134455064804806");
  private static final int TICKET_CLASS = 0;  // Regular ticket
  private static final String CONFERENCE_ID = "Åø"; // Ensure non-number non ASCII can be handled
  private static final BigInteger TICKET_SECRET = new BigInteger("48646");
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");
  private static final byte[] CONTEXT = new byte[]{0x42};

  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair attestorKeys;
  private static AsymmetricCipherKeyPair ticketIssuerKeys;
  private static final byte[] macKey = new byte[16];
  private static AsymmetricCipherKeyPair keys;
  private static SignedIdentifierAttestation signed;
  private static Ticket ticket;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;

  @Mock
  AttestedObject<Ticket> mockedUseTicket;
  @Mock
  UnpredictableNumberBundle mockedUn;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());

    crypto = new AttestationCrypto(rand);
    subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    attestorKeys = SignatureUtility.constructECKeys(rand);
    ticketIssuerKeys = SignatureUtility.constructECKeys(rand);
    rand.nextBytes(macKey);
    keys = SignatureUtility.constructECKeysWithSmallestY(rand);

    IdentifierAttestation att = HelperTest
            .makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    signed = new SignedIdentifierAttestation(att, attestorKeys);
    ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketIssuerKeys, TICKET_SECRET);
  }

  private static Stream<Arguments> unProvider() {
    UnpredictableNumberTool unMac = new UNMac(rand, macKey, DOMAIN, UnpredictableNumberTool.DEFAULT_VALIDITY_IN_MS);
    UnpredictableNumberBundle unbMac = unMac.getUnpredictableNumberBundle();
    UnpredictableNumberBundle unbMacContext = unMac.getUnpredictableNumberBundle(CONTEXT);
    UnpredictableNumberTool unSig = new UNSignature(rand, keys, DOMAIN, UnpredictableNumberTool.DEFAULT_VALIDITY_IN_MS);
    UnpredictableNumberBundle unbSig = unSig.getUnpredictableNumberBundle();
    UnpredictableNumberBundle unbSigContext = unSig.getUnpredictableNumberBundle(CONTEXT);
    return Stream.of(
            Arguments.of(unMac, unbMac,
                    new AttestedObject<>(ticket, signed, ATTESTATION_SECRET,
                            TICKET_SECRET, unbMac.getNumber().getBytes(StandardCharsets.UTF_8), crypto)),
            Arguments.of(unSig, unbSig,
                    new AttestedObject<>(ticket, signed, ATTESTATION_SECRET,
                            TICKET_SECRET, unbSig.getNumber().getBytes(StandardCharsets.UTF_8), crypto)),
            Arguments.of(unMac, unbMacContext,
                    new AttestedObject<>(ticket, signed, ATTESTATION_SECRET,
                            TICKET_SECRET, unbMacContext.getNumber().getBytes(StandardCharsets.UTF_8), crypto)),
            Arguments.of(unSig, unbSigContext,
                    new AttestedObject<>(ticket, signed, ATTESTATION_SECRET,
                            TICKET_SECRET, unbSigContext.getNumber().getBytes(StandardCharsets.UTF_8), crypto))
    );
  }

  @BeforeEach
  public void makeUseTicket() {
    MockitoAnnotations.openMocks(this);

    Mockito.when(mockedUseTicket.verify()).thenReturn(true);
    Mockito.when(mockedUseTicket.getDerEncoding()).thenReturn(new byte[]{0x00});
    Mockito.when(mockedUseTicket.getAttestedUserKey()).thenReturn(subjectKeys.getPublic());

    Mockito.when(mockedUn.getDomain()).thenReturn(DOMAIN);
    Mockito.when(mockedUn.getExpiration()).thenReturn(Long.MAX_VALUE);
    Mockito.when(mockedUn.getRandomness()).thenReturn(new byte[UnpredictableNumberTool.BYTES_IN_SEED]);
    Mockito.when(mockedUn.getNumber()).thenReturn("abcdefghijk");
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void sunshine(UnpredictableNumberTool un, UnpredictableNumberBundle unb, AttestedObject<Ticket> useTicket) {
    UseTicketBundle bundle = new UseTicketBundle(useTicket, unb, subjectKeys.getPrivate());
    assertTrue(bundle.verify());
    assertTrue(bundle.validateAndVerify(un));
  }

  @Test
  void signaturePKValidation() {
    UnpredictableNumberTool unSig = new UNSignature(rand, keys, DOMAIN, UnpredictableNumberTool.DEFAULT_VALIDITY_IN_MS);
    UnpredictableNumberBundle unbSig = unSig.getUnpredictableNumberBundle();
    UnpredictableNumberTool unSigPK = new UNSignature(keys.getPublic(), DOMAIN);
    assertTrue(unSigPK.validateUnpredictableNumber(unbSig.getNumber(), unbSig.getRandomness(), unbSig.getExpiration(), unbSig.getContext()));
  }

  @Test
  void otherConstructorSig() {
    UnpredictableNumberTool unSig = new UNSignature(keys, DOMAIN);
    UnpredictableNumberBundle unbSig = unSig.getUnpredictableNumberBundle();
    UnpredictableNumberTool unSigPK = new UNSignature(keys.getPublic(), DOMAIN);
    assertTrue(unSigPK.validateUnpredictableNumber(unbSig.getNumber(), unbSig.getRandomness(), unbSig.getExpiration()));
  }

  @Test
  void otherConstructorMac() {
    UnpredictableNumberTool unSig = new UNMac(macKey, DOMAIN);
    UnpredictableNumberBundle unbSig = unSig.getUnpredictableNumberBundle();
    UnpredictableNumberTool unSigPK = new UNMac(macKey, DOMAIN);
    assertTrue(unSigPK.validateUnpredictableNumber(unbSig.getNumber(), unbSig.getRandomness(), unbSig.getExpiration()));
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void testDeEncoding1(UnpredictableNumberTool un, UnpredictableNumberBundle unb, AttestedObject<Ticket> useTicket) throws Exception {
    UseTicketBundle bundle = new UseTicketBundle(useTicket, unb, subjectKeys.getPrivate());
    String refJson = bundle.getJsonBundle();
    UseTicketBundle newBundle = new UseTicketBundle(refJson, ticketIssuerKeys.getPublic(), attestorKeys.getPublic());
    assertTrue(newBundle.verify());
    assertTrue(newBundle.validateAndVerify(un));
    assertEquals(refJson, newBundle.getJsonBundle());
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void testDeEncoding2(UnpredictableNumberTool un, UnpredictableNumberBundle unb, AttestedObject<Ticket> useTicket) throws Exception {
    UseTicketBundle bundle = new UseTicketBundle(useTicket, unb, subjectKeys.getPrivate());
    String refJson = bundle.getJsonBundle();
    UseTicketBundle newBundle = new UseTicketBundle(bundle.getUseTicket(), bundle.getUn(), bundle.getSignature());
    assertTrue(newBundle.verify());
    assertTrue(newBundle.validateAndVerify(un));
    assertEquals(refJson, newBundle.getJsonBundle());
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void sanity(UnpredictableNumberTool un, UnpredictableNumberBundle unb) throws Exception {
    UnpredictableNumberBundle newerUn = un.getUnpredictableNumberBundle();
    ObjectMapper jsonMapper = new ObjectMapper();
    // Verify that the ticket is different
    assertNotEquals(jsonMapper.writeValueAsString(unb), jsonMapper.writeValueAsString(newerUn));
  }

  @Test
  void sanityTimeMac() throws Exception {
    SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    UnpredictableNumberTool unt = new UNMac(rand, macKey, DOMAIN, UNMac.DEFAULT_VALIDITY_IN_MS);
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    rand.setSeed("seed".getBytes()); // Reset the randomness generator
    Thread.sleep(2); // Ensure the expiration changes
    UnpredictableNumberBundle newerUn = unt.getUnpredictableNumberBundle();
    ObjectMapper jsonMapper = new ObjectMapper();
    // Verify that the ticket is different
    assertNotEquals(jsonMapper.writeValueAsString(un), jsonMapper.writeValueAsString(newerUn));
  }

  @Test
  void sanityTimeSig() throws Exception {
    SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    UnpredictableNumberTool unt = new UNSignature(rand, keys, DOMAIN, UNMac.DEFAULT_VALIDITY_IN_MS);
    UnpredictableNumberBundle un = unt.getUnpredictableNumberBundle();
    rand.setSeed("seed".getBytes()); // Reset the randomness generator
    Thread.sleep(2); // Ensure the expiration changes
    UnpredictableNumberBundle newerUn = unt.getUnpredictableNumberBundle();
    ObjectMapper jsonMapper = new ObjectMapper();
    // Verify that the ticket is different
    assertNotEquals(jsonMapper.writeValueAsString(un), jsonMapper.writeValueAsString(newerUn));
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void worksInTheFuture(UnpredictableNumberTool un) {
    UnpredictableNumberBundle unb = un.getUnpredictableNumberBundle();
    // Check it is valid at least 58 min in the future
    assertTrue(unb.getExpiration() > Clock.systemUTC().millis() + 3500 * 1000);
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void unverifiableUseTicketConstructorFailure(UnpredictableNumberTool un, UnpredictableNumberBundle unb) {
    Mockito.when(mockedUseTicket.verify()).thenReturn(false);
    assertThrows(IllegalArgumentException.class, () -> new UseTicketBundle(mockedUseTicket, unb, subjectKeys.getPrivate()));
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void badChallengeSignatureConstructor(UnpredictableNumberTool un, UnpredictableNumberBundle unb) {
    // Return wrong key, it is supposed to be the subjectKey
    Mockito.when(mockedUseTicket.getAttestedUserKey()).thenReturn(attestorKeys.getPublic());
    assertThrows(IllegalArgumentException.class, () -> new UseTicketBundle(mockedUseTicket, unb, subjectKeys.getPrivate()));
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void unverifiableUseTicket(UnpredictableNumberTool un, UnpredictableNumberBundle unb) {
    // Return true first to make test in constructor pass
    Mockito.when(mockedUseTicket.verify()).thenReturn(true).thenReturn(false);
    UseTicketBundle bundle = new UseTicketBundle(mockedUseTicket, unb, subjectKeys.getPrivate());
    assertFalse(bundle.verify());
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void unvalidatableUseTicket(UnpredictableNumberTool un, UnpredictableNumberBundle unb) {
    Mockito.when(mockedUseTicket.checkValidity()).thenReturn(false);
    UseTicketBundle bundle = new UseTicketBundle(mockedUseTicket, unb, subjectKeys.getPrivate());
    assertFalse(bundle.validateAndVerify(un));
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void invalidUn(UnpredictableNumberTool un, UnpredictableNumberBundle unb, AttestedObject<Ticket> useTicket) {
    Mockito.when(mockedUn.getNumber()).thenReturn("somethingwrong");

    UseTicketBundle bundle = new UseTicketBundle(useTicket, mockedUn, subjectKeys.getPrivate());
    assertFalse(bundle.validateAndVerify(un));
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void wrongUnUsed(UnpredictableNumberTool un, UnpredictableNumberBundle unb, AttestedObject<Ticket> useTicket) {
    UnpredictableNumberBundle wrongUn = un.getUnpredictableNumberBundle();
    UseTicketBundle bundle = new UseTicketBundle(useTicket, wrongUn, subjectKeys.getPrivate());
    assertFalse(bundle.validateAndVerify(un));
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void wrongContext(UnpredictableNumberTool un, UnpredictableNumberBundle unb) {
    assertFalse(un.validateUnpredictableNumber(unb.getNumber(), unb.getRandomness(), unb.getExpiration(), new byte[]{0x01}));
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void wrongExpiration(UnpredictableNumberTool un, UnpredictableNumberBundle unb) {
    assertFalse(un.validateUnpredictableNumber(unb.getNumber(), unb.getRandomness(), unb.getExpiration() + 1, unb.getContext()));
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void wrongRandomness(UnpredictableNumberTool un, UnpredictableNumberBundle unb) {
    assertFalse(un.validateUnpredictableNumber(unb.getNumber(), new byte[UnpredictableNumberTool.BYTES_IN_SEED], unb.getExpiration(), unb.getContext()));
  }

  @ParameterizedTest
  @MethodSource("unProvider")
  void wrongUn(UnpredictableNumberTool un, UnpredictableNumberBundle unb) {
    assertFalse(un.validateUnpredictableNumber("aabbccdd", unb.getRandomness(), unb.getExpiration(), unb.getContext()));
  }
}
