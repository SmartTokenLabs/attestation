package org.tokenscript.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.IdentifierAttestation;
import com.alphawallet.attestation.SignedIdentityAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.devcon.ticket.Ticket;
import org.devcon.ticket.TicketDecoder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tokenscript.eip712.Eip712Test;
import org.tokenscript.eip712.FullEip712InternalData;

public class EIP712AuthenticationTest {
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
  private static Eip712AuthValidator validator;
  private static Eip712AuthIssuer issuer;
  private static AuthenticatorEncoder authenticator;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    attestorKeys = SignatureUtility.constructECKeys(SECP364R1, rand);
    ticketKeys = SignatureUtility.constructECKeys(SECP364R1, rand);
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    authenticator = new AuthenticatorEncoder(1, rand);
    validator = new Eip712AuthValidator(decoder, authenticator, attestorKeys.getPublic(), validatorDomain);
    issuer = new Eip712AuthIssuer(userKeys.getPrivate(), authenticator);
  }

  private static AttestedObject<Ticket> makeAttestedTicket() {
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(userKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedIdentityAttestation signed = new SignedIdentityAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketKeys, TICKET_SECRET);
    AttestedObject attestedTicket = new AttestedObject<Ticket>(ticket, signed, userKeys, ATTESTATION_SECRET, TICKET_SECRET, crypto);
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
    Eip712Test.validateEncoding(authenticator, token);
  }

  @Test
  public void testNewChainID() throws Exception {
    AuthenticatorEncoder localAuthenticator = new AuthenticatorEncoder(42, rand);
    Eip712AuthIssuer localIssuer = new Eip712AuthIssuer(userKeys.getPrivate(), localAuthenticator);
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = localIssuer.buildSignedToken(attestedTicket, validatorDomain);
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    Eip712AuthValidator localValidator = new Eip712AuthValidator(decoder, localAuthenticator, attestorKeys.getPublic(), validatorDomain);
    assertTrue(localValidator.validateRequest(token));
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void testConsistency() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    long testTimestamp = Clock.systemUTC().millis();
    Eip712AuthIssuer testIssuer = new TestEip712Authentication(userKeys.getPrivate(), new TestAuthenticatorEncoder(), testTimestamp);
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    String newToken = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertEquals(token, newToken);
  }

  @Test
  public void testDifferenceWithDifferentChainIds() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    Eip712AuthIssuer testIssuer1 = new Eip712AuthIssuer(userKeys.getPrivate(), new TestAuthenticatorEncoder("0.1", 1));
    String token = testIssuer1.buildSignedToken(attestedTicket, validatorDomain);
    String equalToken = testIssuer1.buildSignedToken(attestedTicket, validatorDomain);
    assertEquals(token, equalToken);
    Eip712AuthIssuer testIssuer2 = new Eip712AuthIssuer(userKeys.getPrivate(), new TestAuthenticatorEncoder("0.1", 42));
    String newToken = testIssuer2.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(token.equals(newToken));
  }

  @Test
  public void nullInput() {
    assertFalse(validator.validateRequest(null));
  }

  @Test
  public void wrongAttestedKey() throws Exception {
    AsymmetricCipherKeyPair newKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(newKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedIdentityAttestation signed = new SignedIdentityAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketKeys, TICKET_SECRET);
    AttestedObject attestedTicket = new AttestedObject<Ticket>(ticket, signed, newKeys, ATTESTATION_SECRET, TICKET_SECRET, crypto);

    String token = issuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void wrongSignature() throws Exception {
    AsymmetricCipherKeyPair newKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    Eip712AuthIssuer newIssuer = new Eip712AuthIssuer(newKeys.getPrivate(), authenticator.getChainId());
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = newIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void tooNew() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    long testTimestamp = Clock.systemUTC().millis() + 2 * validator.DEFAULT_TIME_LIMIT_MS;
    Eip712AuthIssuer testIssuer = new TestEip712Authentication(userKeys.getPrivate(), new TestAuthenticatorEncoder(), testTimestamp);
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void tooOld() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = issuer.buildSignedToken(attestedTicket, validatorDomain);
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    Eip712AuthValidator newValidator = new Eip712AuthValidator(decoder, authenticator, attestorKeys.getPublic(), validatorDomain, 0);
    Thread.sleep(1);
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
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    assertThrows( RuntimeException.class, () -> {
      new Eip712AuthValidator(decoder, authenticator, attestorKeys.getPublic(), "www.noHttpPrefix.com");
    });
  }

  @Test
  public void invalidDomainIssuer() {
    AttestedObject attestedTicket = makeAttestedTicket();
    assertThrows( RuntimeException.class, () -> {
      AuthenticatorEncoder authenticator = new AuthenticatorEncoder(1, rand);
      Eip712AuthIssuer issuer = new Eip712AuthIssuer(userKeys.getPrivate(), authenticator);
      issuer.buildSignedToken(attestedTicket, "www.noHttpPrefix.com");
    });
  }

  @Test
  public void invalidVersion() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    Eip712AuthIssuer testIssuer = new Eip712AuthIssuer(userKeys.getPrivate(), new TestAuthenticatorEncoder("2.2", 1));
    String token = testIssuer.buildSignedToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void consistentSalt() {
    String salt = authenticator.getSalt();
    assertNotNull(salt);
    String otherSalt = authenticator.getSalt();
    assertEquals(salt, otherSalt);
  }

  private class TestEip712Authentication extends Eip712AuthIssuer {
    private final long testTimestamp;

    public TestEip712Authentication(AsymmetricKeyParameter signingKey, AuthenticatorEncoder authenticator, long testTimestamp) {
      super(signingKey, authenticator);
      this.testTimestamp = testTimestamp;
    }

    @Override
    public String buildSignedToken(AttestedObject attestedObject, String webDomain) throws JsonProcessingException {
      String encodedObject = URLUtility.encodeData(attestedObject.getDerEncoding());
      FullEip712InternalData auth = new FullEip712InternalData(
          AuthenticatorEncoder.USAGE_VALUE, encodedObject,
          testTimestamp);
      return buildSignedTokenFromJsonObject(auth, webDomain);
    }
  }

  @Test
  public void testHu() {
    //String request = "{\"signatureInHex\":\"0xe5437dc933856e9292d81f82f18c2f024615d7dc670ab0b0bd1da28648a5e2ff65076d89e922a483b10d3717ebf51460a0d668195c730ebe5ca930cb5cf77bf81c\",\"jsonRpc\":\"2.0\",\"chainId\":3,\"jsonSigned\":\"{\\\"domain\\\":{\\\"name\\\":\\\"http://wwww.attestation.id\\\",\\\"version\\\":\\\"0.1\\\",\\\"chainId\\\":3},\\\"message\\\":{\\\"payload\\\":\\\"MIIBLQIBADCCASYEQQQjSSuHoeDrfflLEOw95Vc0kZHB6cz3pxpVsT6wgYXQaB9UHrziOybmB9Og6cD86Du1nP333I3k5vUogUa_9n5NBCAP_KXLfYvvGHBOi2_zCYSpVm6IUjt7_hQOTCxeoBhAGARBBApQ_xvQuESGbluXOJYfNw7J29n3iyOrYVtQ8c-og79wIylp4AnZzQ-wEr_YZ2O5jTHLECJlsDUzwZ9TZlNP5ygEfAAAAXg_rNwOdH-jiuhdX2vhv-GKUEDz1PufxLdKSXLUQOe9y48bbCgvIdwS3UO9FbhmQzMgQauXAQNX16mVOdMvZKl24jVJjabMI6iY8lztbg-HkIsPKqDcH4B8xdJGAYb3IzySfn2y3McDwOUAtlPKgic7e_rYBF2FpHA=\\\",\\\"description\\\":\\\"Linking Ethereum address to phone or email\\\",\\\"timestamp\\\":\\\"Wed Mar 17 2021 12:13:16 GMT+0200\\\",\\\"identifier\\\":\\\"test@test.com\\\",\\\"address\\\":\\\"0x2f21dc12dd43bd15b86643332041ab97010357d7\\\"},\\\"primaryType\\\":\\\"AttestationRequest\\\",\\\"types\\\":{\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"}],\\\"AttestationRequest\\\":[{\\\"name\\\":\\\"address\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"}]}}\"}";
//    String request = "{\"signatureInHex\":\"0x6e2a95d19eb26e8a01b11d4ea694387a97f64030c880e0fd96b8378b913b4ec1632335d42781185cbd1044e6706eec1d08dafb063f86a47bf19b10faa85e07781c\",\"jsonRpc\":\"2.0\",\"chainId\":3,\"jsonSigned\":\"{\\\"domain\\\":{\\\"name\\\":\\\"http://wwww.attestation.id\\\",\\\"version\\\":\\\"0.1\\\",\\\"chainId\\\":3},\\\"message\\\":{\\\"payload\\\":\\\"MIIBLQIBADCCASYEQQQjSSuHoeDrfflLEOw95Vc0kZHB6cz3pxpVsT6wgYXQaB9UHrziOybmB9Og6cD86Du1nP333I3k5vUogUa_9n5NBCADa4wSP3noAIpweaXuCgNJQGWIikjZiisEjFKg7SS_UQRBBAze02glDx9vj1SU6EDo3oNYR-qRam7m_tzhPffMchQgLTEM6Cf1hyytuly5ZfbhTyLKb90cTqw1QIoDIqn8W6AEfAAAAXhA_G5sdH-jiuhdX2vhv-GKUEDz1PufxLdKSXLUQOe9y48bbCgvIdwS3UO9FbhmQzMgQauXAQNX16mVOdMvZKl24jVJjabMI6iY8lztbg-HkIsPKqDcH4B8xdJGAYb3IzySfn2y3McDwOUAtlPKgic7e_rYBF2FpHA=\\\",\\\"description\\\":\\\"Linking Ethereum address to phone or email\\\",\\\"timestamp\\\":\\\"Wed Mar 17 2021 18:19:49 GMT+0200\\\",\\\"identifier\\\":\\\"test@test.com\\\",\\\"address\\\":\\\"0x2f21dc12dd43bd15b86643332041ab97010357d7\\\"},\\\"primaryType\\\":\\\"AttestationRequest\\\",\\\"types\\\":{\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"}],\\\"AttestationRequest\\\":[{\\\"name\\\":\\\"address\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"}]}}\"}";
    String request = "{\"signatureInHex\":\"0xa0a1b16204c11553af7d295681b5500a523f12bd9e188929e696b8bb65855e587848b9ca442cadb0ce6667bc885f58104dd01d63a650cbd087a99abe6afa0e8e1b\",\"jsonRpc\":\"2.0\",\"chainId\":1,\"jsonSigned\":\"{\\\"domain\\\":{},\\\"message\\\":{\\\"start\\\":\\\"Thu Mar 18 2021 13:41:19 GMT+0100\\\"},\\\"primaryType\\\":\\\"Attest\\\",\\\"types\\\":{\\\"EIP712Domain\\\":[],\\\"Attest\\\":[{\\\"name\\\":\\\"start\\\",\\\"type\\\":\\\"string\\\"}]}}\"}";
    TestAuthenticatorEncoder encoder = new TestAuthenticatorEncoder("1", 1);
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    Eip712AuthValidator eiprequest = new Eip712AuthValidator(decoder, encoder,
        attestorKeys.getPublic(), "Certificate");
    assertTrue(eiprequest.validateRequest(request));
  }

  private class TestAuthenticatorEncoder extends AuthenticatorEncoder {
    private String protoVersion = super.PROTOCOL_VERSION;

    public TestAuthenticatorEncoder(String protoVersion, long chainId) {
      super(chainId, new SecureRandom());
      this.protoVersion = protoVersion;
    }

    public TestAuthenticatorEncoder() {
      super(1, new SecureRandom());
    }

    @Override
    public String getSalt() {
      return "0102030405060708090001020304050607080900010203040506070809000102";
    }

    @Override
    public String getProtocolVersion() {
      return protoVersion;
    }
  }
}
