package org.tokenscript.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.devcon.ticket.Ticket;
import org.devcon.ticket.DevconTicketDecoder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.tokenscript.attestation.AttestedObject;
import org.tokenscript.attestation.AttestedObjectDecoder;
import org.tokenscript.attestation.HelperTest;
import org.tokenscript.attestation.IdentifierAttestation;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.SignedIdentifierAttestation;
import org.tokenscript.attestation.Timestamp;
import org.tokenscript.attestation.core.ASNEncodable;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.URLUtility;
import org.tokenscript.eip712.Eip712Test;
import org.tokenscript.eip712.FullEip712InternalData;

public class EIP712ObjectTest {
  private static final String validatorDomain = "http://www.hotelbogota.com";

  private static final X9ECParameters SECP364R1 = SECNamedCurves.getByName("secp384r1");
  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("546048445646851568430134455064804806");
  private static final int TICKET_CLASS = 0;  // Regular ticket
  private static final String CONFERENCE_ID = "6";
  private static final BigInteger TICKET_SECRET = new BigInteger("48646");
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");
  private static final byte[] UN = new byte[] { 0x42, 0x42 };

  private static AsymmetricCipherKeyPair userKeys, attestorKeys, ticketKeys;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;
  private static Eip712ObjectValidator validator;
  private static Eip712ObjectSigner issuer;
  private static AuthenticatorEncoder encoder;

  @BeforeEach
  public void init() {
    MockitoAnnotations.initMocks(this);
  }

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    attestorKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    ticketKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    ObjectDecoder<Ticket> ticketDecoder = new DevconTicketDecoder(ticketKeys.getPublic());
    ObjectDecoder<AttestedObject<Ticket>> attestedObjectDecoder = new AttestedObjectDecoder<Ticket>(ticketDecoder,
        attestorKeys.getPublic());
    encoder = new AuthenticatorEncoder(0, rand);
    validator = new Eip712ObjectValidator(attestedObjectDecoder, encoder, validatorDomain);
    issuer = new Eip712ObjectSigner(userKeys.getPrivate(), encoder);
  }

  private static AttestedObject<Ticket> makeAttestedTicket() {
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(userKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketKeys, TICKET_SECRET);
    AttestedObject attestedTicket = new AttestedObject<Ticket>(ticket, signed, ATTESTATION_SECRET, TICKET_SECRET, UN, crypto);
    assertTrue(attestedTicket.verify());
    assertTrue(attestedTicket.checkValidity());
    return attestedTicket;
  }

  @Test
  public void legalRequest() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = issuer.buildSignedToken(attestedTicket, validatorDomain);
    assertTrue(validator.validateRequest(token));
  }

  @Test
  public void eipEncoding() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = issuer.buildSignedToken(attestedTicket, validatorDomain);
    Eip712Test.validateEncoding(encoder, token);
  }

  @Test
  public void eipEncodingDefaultIssuer() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = issuer.buildSignedToken(attestedTicket, validatorDomain);
    Eip712Test.validateEncoding(encoder, token);
  }

  @Test
  public void testNewChainID() throws Exception {
    AuthenticatorEncoder localAuthenticator = new AuthenticatorEncoder(42, rand);
    Eip712ObjectSigner localIssuer = new Eip712ObjectSigner(userKeys.getPrivate(), localAuthenticator);
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = localIssuer.buildSignedToken(attestedTicket, validatorDomain);
    ObjectDecoder<Ticket> ticketDecoder = new DevconTicketDecoder(ticketKeys.getPublic());
    ObjectDecoder<AttestedObject<Ticket>> attestedObjectDecoder = new AttestedObjectDecoder<Ticket>(ticketDecoder,
        attestorKeys.getPublic());
    Eip712ObjectValidator localValidator = new Eip712ObjectValidator(attestedObjectDecoder, localAuthenticator,
        validatorDomain);
    assertTrue(localValidator.validateRequest(token));
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void testConsistency() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    long testTimestamp = Clock.systemUTC().millis();
    Eip712ObjectSigner testIssuer = new TestEip712ObjectSigner(userKeys.getPrivate(), new TestAuthenticatorEncoder(), testTimestamp);
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    String newToken = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertEquals(token, newToken);
  }

  @Test
  public void nullInput() {
    assertFalse(validator.validateRequest(null));
  }

  @Test
  public void wrongAttestedKey() throws Exception {
    AsymmetricCipherKeyPair newKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(newKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketKeys, TICKET_SECRET);
    AttestedObject attestedTicket = new AttestedObject<Ticket>(ticket, signed, ATTESTATION_SECRET, TICKET_SECRET, UN, crypto);

    String token = issuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void wrongSignature() throws Exception {
    AsymmetricCipherKeyPair newKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    Eip712ObjectSigner newIssuer = new Eip712ObjectSigner(newKeys.getPrivate(), new AuthenticatorEncoder(encoder.getChainId(),rand));
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = newIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void tooNew() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    long testTimestamp = Clock.systemUTC().millis() + 2 * Timestamp.ALLOWED_ROUNDING;
    Eip712ObjectSigner testIssuer = new TestEip712ObjectSigner(userKeys.getPrivate(), new TestAuthenticatorEncoder(), testTimestamp);
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void tooOld() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    long testTimestamp = 10000;
    Eip712ObjectSigner testIssuer = new TestEip712ObjectSigner(userKeys.getPrivate(), new TestAuthenticatorEncoder(), testTimestamp);
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    ObjectDecoder<Ticket> decoder = new DevconTicketDecoder(ticketKeys.getPublic());
    Eip712ObjectValidator newValidator = new Eip712ObjectValidator(decoder, encoder, validatorDomain);
    assertFalse(newValidator.validateRequest(token));
  }

  @Test
  public void incorrectModifiedToken() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = issuer.buildSignedToken(attestedTicket, validatorDomain);
    byte[] tokenBytes = token.getBytes(StandardCharsets.UTF_8);
    // Flip a bit
    tokenBytes[40] ^= 0x01;
    assertFalse(validator.validateRequest(new String(tokenBytes, StandardCharsets.UTF_8)));
  }

  @Test
  public void incorrectDomain() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    // Extra a in domain
    String token = issuer.buildSignedToken(attestedTicket, "http://www.hotelbogotaa.com");
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void invalidDomainVerifier() {
    ObjectDecoder<Ticket> decoder = new DevconTicketDecoder(ticketKeys.getPublic());
    assertThrows( RuntimeException.class, () -> {
      new Eip712ObjectValidator(decoder, encoder, "www.noHttpPrefix.com");
    });
  }

  @Test
  public void invalidDomainIssuer() {
    AttestedObject attestedTicket = makeAttestedTicket();
    assertThrows( RuntimeException.class, () -> {
      AuthenticatorEncoder authenticator = new AuthenticatorEncoder(1, rand);
      Eip712ObjectSigner issuer = new Eip712ObjectSigner(userKeys.getPrivate(), authenticator);
      issuer.buildSignedToken(attestedTicket, "www.noHttpPrefix.com");
    });
  }

  @Test
  public void invalidVersion() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    Eip712ObjectSigner testIssuer = new Eip712ObjectSigner(userKeys.getPrivate(), new TestAuthenticatorEncoder("2.2", encoder.getChainId()));
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void badDescription() {
    AttestedObject attestedTicket = makeAttestedTicket();
    Eip712ObjectSigner testIssuer = new Eip712ObjectSigner(userKeys.getPrivate(),
        new TestAuthenticatorEncoder(encoder.getVerifyingContract(), encoder.getSalt(),
            "Wrong description", encoder.getProtocolVersion(), encoder.getChainId()));
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void badVerifyingContract() {
    AttestedObject attestedTicket = makeAttestedTicket();
    Eip712ObjectSigner testIssuer = new Eip712ObjectSigner(userKeys.getPrivate(),
        new TestAuthenticatorEncoder("0xDEADBEEF", encoder.getSalt(),
            "Wrong description", encoder.getProtocolVersion(), encoder.getChainId()));
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Mock
  AttestedObject mockedAttestedObject;
  @Mock
  ObjectDecoder<AttestedObject<Ticket>> mockedDecoder;
  @Test
  public void unvalidatableUnderlyingObject() throws Exception {
    Mockito.when(mockedAttestedObject.checkValidity()).thenReturn(false);
    Mockito.when(mockedAttestedObject.verify()).thenReturn(true);
    Mockito.when(mockedAttestedObject.getDerEncoding()).thenReturn(new byte[] {0x42});
    Mockito.when(mockedAttestedObject.getAttestedUserKey()).thenReturn(userKeys.getPublic());

    Mockito.when(mockedDecoder.decode(ArgumentMatchers.any())).thenReturn(mockedAttestedObject);
    Eip712ObjectValidator newValidator = new Eip712ObjectValidator(mockedDecoder, encoder, validatorDomain);
    String token = issuer.buildSignedToken(mockedAttestedObject, validatorDomain);
    assertFalse(newValidator.validateRequest(token));
  }

  @Test
  public void unverifiableUnderlyingObject() throws Exception {
    Mockito.when(mockedAttestedObject.checkValidity()).thenReturn(true);
    Mockito.when(mockedAttestedObject.verify()).thenReturn(false);
    Mockito.when(mockedAttestedObject.getDerEncoding()).thenReturn(new byte[] {0x42});
    Mockito.when(mockedAttestedObject.getAttestedUserKey()).thenReturn(userKeys.getPublic());

    Mockito.when(mockedDecoder.decode(ArgumentMatchers.any())).thenReturn(mockedAttestedObject);
    Eip712ObjectValidator newValidator = new Eip712ObjectValidator(mockedDecoder, encoder, validatorDomain);
    String token = issuer.buildSignedToken(mockedAttestedObject, validatorDomain);
    assertFalse(newValidator.validateRequest(token));
  }

  @Test
  public void consistentSalt() {
    String salt = encoder.getSalt();
    assertNotNull(salt);
    String otherSalt = encoder.getSalt();
    assertEquals(salt, otherSalt);
  }

  private class TestEip712ObjectSigner<T extends ASNEncodable> extends Eip712ObjectSigner<T> {
    private final Timestamp testTimestamp;

    public TestEip712ObjectSigner(AsymmetricKeyParameter signingKey, AuthenticatorEncoder authenticator, long testTimestamp) {
      super(signingKey, authenticator);
      this.testTimestamp = new Timestamp(testTimestamp);
    }

    @Override
    public String buildSignedToken(T attestedObject, String webDomain) {
      try {
        String encodedObject = URLUtility.encodeData(attestedObject.getDerEncoding());
        FullEip712InternalData auth = new FullEip712InternalData(
            encoder.getUsageValue(), encodedObject, testTimestamp);
        return buildSignedTokenFromJsonObject(auth, webDomain);
      } catch (Exception e) {
        throw new RuntimeException("", e);
      }
    }
  }

  private class TestAuthenticatorEncoder extends AuthenticatorEncoder {
    private String protoVersion;
    private String usageValue;
    private String salt;
    private String verifyingContract;

    public TestAuthenticatorEncoder() {
      this(encoder.getProtocolVersion(), encoder.getChainId());
    }

    public TestAuthenticatorEncoder(String protoVersion, long chainId) {
      this(encoder.getVerifyingContract(), encoder.getSalt(), encoder.getUsageValue(), protoVersion, chainId);
    }

    public TestAuthenticatorEncoder(String verifyingContract, String salt, String usageValue, String protoVersion, long chainId) {
      super(chainId, new SecureRandom());
      this.protoVersion = protoVersion;
      this.usageValue = usageValue;
      this.salt = salt;
      this.verifyingContract = verifyingContract;
    }

    @Override
    public String getUsageValue() {
      return usageValue;
    }

    @Override
    public String getSalt() {
      return salt;
    }

    @Override
    public String getProtocolVersion() {
      return protoVersion;
    }

    @Override
    public String getVerifyingContract() {
      return verifyingContract;
    }
  }
}