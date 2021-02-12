package org.tokenscript.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.Attestation;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.SignedAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Domain;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Message;
import java.io.IOException;
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
import org.tokenscript.auth.model.InternalAuthenticationData;

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
  private static Eip712Validator validator;
  private static Eip712Issuer issuer;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    attestorKeys = SignatureUtility.constructECKeys(SECP364R1, rand);
    ticketKeys = SignatureUtility.constructECKeys(SECP364R1, rand);
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    validator = new Eip712Validator(decoder, attestorKeys.getPublic(), validatorDomain);
    Eip712Authenticator authenticator = new Eip712Authenticator(rand);
    issuer = new Eip712Issuer(userKeys, authenticator);
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
  public void testNewChainID() {
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = issuer.makeToken(attestedTicket, validatorDomain, 1);
    assertTrue(validator.validateRequest(token));
  }

  @Test
  public void testConsistency() {
    AttestedObject attestedTicket = makeAttestedTicket();
    Eip712Issuer testIssuer = new Eip712Issuer(userKeys, new TestAuthenticator(System.currentTimeMillis()));
    String token = testIssuer.makeToken(attestedTicket, validatorDomain);
    String newToken = testIssuer.makeToken(attestedTicket, validatorDomain);
    assertEquals(token, newToken);
  }

  @Test
  public void testDifferenceWithDifferentChainIds() {
    AttestedObject attestedTicket = makeAttestedTicket();
    Eip712Issuer testIssuer = new Eip712Issuer(userKeys, new TestAuthenticator(System.currentTimeMillis()));
    String token = testIssuer.makeToken(attestedTicket, validatorDomain, 0);
    String newToken = testIssuer.makeToken(attestedTicket, validatorDomain, 1);
    assertFalse(token.equals(newToken));
  }

  @Test
  public void nullInput() {
    assertFalse(validator.validateRequest(null));
  }

  @Test
  public void wrongAttestedKey() {
    AsymmetricCipherKeyPair newKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    Attestation att = HelperTest.makeUnsignedStandardAtt(newKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedAttestation signed = new SignedAttestation(att, attestorKeys);
    Ticket ticket = new Ticket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS, ticketKeys, TICKET_SECRET);
    AttestedObject attestedTicket = new AttestedObject<Ticket>(ticket, signed, newKeys, ATTESTATION_SECRET, TICKET_SECRET, crypto);

    String token = issuer.makeToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void wrongSignature() {
    AsymmetricCipherKeyPair newKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    Eip712Issuer newIssuer = new Eip712Issuer(newKeys);
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = newIssuer.makeToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void tooNew() {
    AttestedObject attestedTicket = makeAttestedTicket();
    Eip712Issuer testIssuer = new Eip712Issuer(userKeys, new TestAuthenticator(System.currentTimeMillis() + 2* validator.TIMELIMIT_IN_MS));
    String token = testIssuer.makeToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void tooOld() throws Exception {
    AttestedObject attestedTicket = makeAttestedTicket();
    String token = issuer.makeToken(attestedTicket, validatorDomain);
    AttestableObjectDecoder<Ticket> decoder = new TicketDecoder(ticketKeys.getPublic());
    Eip712Validator newValidator = new Eip712Validator(decoder, attestorKeys.getPublic(), validatorDomain, 0);
    Thread.sleep(1);
    assertFalse(newValidator.validateRequest(token));
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
      new Eip712Validator(decoder, attestorKeys.getPublic(), "www.noHttpPrefix.com");
    });
  }

  @Test
  public void invalidDomainIssuer() {
    assertThrows( RuntimeException.class, () -> {
      Eip712Authenticator authenticator = new Eip712Authenticator(rand);
      Eip712Issuer issuer = new Eip712Issuer(userKeys, authenticator);
      issuer.makeToken(null, "www.noHttpPrefix.com");
    });
  }

  @Test
  public void invalidVersion() {
    AttestedObject attestedTicket = makeAttestedTicket();
    Eip712Issuer testIssuer = new Eip712Issuer(userKeys, new TestAuthenticator("2.2", System.currentTimeMillis()));
    String token = testIssuer.makeToken(attestedTicket, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  private class TestAuthenticator extends Eip712Authenticator {
    private final long timeStamp;
    private String protoVersion = super.PROTOCOL_VERSION;

    public TestAuthenticator(String protoVersion, long timeStamp) {
      this(timeStamp);
      this.protoVersion = protoVersion;
    }

    public TestAuthenticator(long timestamp) {
      super(null);
      this.timeStamp = timestamp;
    }

    @Override
    public String jsonEncode(String payload, String webDomain) {
      try {
        InternalAuthenticationData auth = new InternalAuthenticationData(USAGE_VALUE, payload, timeStamp);
        String salt = "0102030405060708090001020304050607080900010203040506070809000102"; // 32 bytes
        StructuredData.EIP712Domain domain = new EIP712Domain(webDomain, protoVersion, null, null, salt);
        StructuredData.EIP712Message message = new EIP712Message(getTypes(), PRIMARY_NAME, auth, domain);
        return mapper.writeValueAsString(message);
      } catch ( IOException e) {
        throw new InternalError("The internal json to object mapping failed");
      }
    }
  }
}
