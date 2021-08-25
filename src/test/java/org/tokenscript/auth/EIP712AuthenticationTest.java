package org.tokenscript.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.AttestableObjectDecoder;
import org.tokenscript.attestation.AttestedObject;
import org.tokenscript.attestation.HelperTest;
import org.tokenscript.attestation.IdentifierAttestation;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.SignedIdentifierAttestation;
import org.tokenscript.attestation.cheque.Cheque;
import org.tokenscript.attestation.cheque.ChequeDecoder;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.URLUtility;
import org.tokenscript.attestation.eip712.Timestamp;
import org.tokenscript.eip712.Eip712Test;
import org.tokenscript.eip712.FullEip712InternalData;

public class EIP712AuthenticationTest {
  private static final String validatorDomain = "http://www.hotelbogota.com";

  private static final X9ECParameters SECP364R1 = SECNamedCurves.getByName("secp384r1");
  private static final String MAIL = "test@test.ts";
  private static final AttestationType TYPE = AttestationType.EMAIL;
  private static final long AMOUNT = 1337;
  private static final long VALIDITY = 1000*60*60*365; // 1 year
  private static final BigInteger CHEQUE_SECRET = new BigInteger("48646");
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");

  private static AsymmetricCipherKeyPair userKeys, attestorKeys, chequeKeys;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;
  private static Eip712AuthValidator validator;
  private static Eip712AuthIssuer issuer;
  private static AuthenticatorEncoder encoder;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    attestorKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    chequeKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    AttestableObjectDecoder<Cheque> decoder = new ChequeDecoder();
    encoder = new AuthenticatorEncoder(1, rand);
    validator = new Eip712AuthValidator(decoder, encoder, attestorKeys.getPublic(), validatorDomain);
    issuer = new Eip712AuthIssuer(userKeys.getPrivate(), encoder);
  }

  private static AttestedObject<Cheque> makeAttestedCheque() {
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(userKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL );
    SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
    Cheque cheque = new Cheque(MAIL, TYPE, AMOUNT, VALIDITY, chequeKeys, CHEQUE_SECRET);
    AttestedObject attestedCheque = new AttestedObject<Cheque>(cheque, signed, userKeys.getPublic(), ATTESTATION_SECRET,
        CHEQUE_SECRET, crypto);
    assertTrue(attestedCheque.verify());
    assertTrue(attestedCheque.checkValidity());
    return attestedCheque;
  }

  @Test
  public void legalRequest() throws Exception {
    AttestedObject attestedCheque = makeAttestedCheque();
    String token = issuer.buildSignedToken(attestedCheque, validatorDomain);
    assertTrue(validator.validateRequest(token));
  }

  @Test
  public void eipEncoding() throws Exception {
    AttestedObject attestedCheque = makeAttestedCheque();
    String token = issuer.buildSignedToken(attestedCheque, validatorDomain);
    Eip712Test.validateEncoding(encoder, token);
  }

  @Test
  public void testNewChainID() throws Exception {
    AuthenticatorEncoder localAuthenticator = new AuthenticatorEncoder(42, rand);
    Eip712AuthIssuer localIssuer = new Eip712AuthIssuer(userKeys.getPrivate(), localAuthenticator);
    AttestedObject attestedCheque = makeAttestedCheque();
    String token = localIssuer.buildSignedToken(attestedCheque, validatorDomain);
    AttestableObjectDecoder<Cheque> decoder = new ChequeDecoder();
    Eip712AuthValidator localValidator = new Eip712AuthValidator(decoder, localAuthenticator, attestorKeys.getPublic(), validatorDomain);
    assertTrue(localValidator.validateRequest(token));
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void testConsistency() throws Exception {
    AttestedObject attestedCheque = makeAttestedCheque();
    long testTimestamp = Clock.systemUTC().millis();
    Eip712AuthIssuer testIssuer = new TestEip712Authentication(userKeys.getPrivate(), new TestAuthenticatorEncoder(), testTimestamp);
    String token = testIssuer.buildSignedToken(attestedCheque, validatorDomain);
    String newToken = testIssuer.buildSignedToken(attestedCheque, validatorDomain);
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
    Cheque cheque = new Cheque(MAIL, TYPE, AMOUNT, VALIDITY, chequeKeys, CHEQUE_SECRET);
    AttestedObject attestedCheque = new AttestedObject<Cheque>(cheque, signed, newKeys.getPublic(), ATTESTATION_SECRET,
        CHEQUE_SECRET, crypto);

    String token = issuer.buildSignedToken(attestedCheque, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void wrongSignature() throws Exception {
    AsymmetricCipherKeyPair newKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    Eip712AuthIssuer newIssuer = new Eip712AuthIssuer(newKeys.getPrivate(), encoder.getChainId());
    AttestedObject attestedCheque = makeAttestedCheque();
    String token = newIssuer.buildSignedToken(attestedCheque, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void tooNew() throws Exception {
    AttestedObject attestedCheque = makeAttestedCheque();
    long testTimestamp = Clock.systemUTC().millis() + 2 * Timestamp.ALLOWED_ROUNDING;
    Eip712AuthIssuer testIssuer = new TestEip712Authentication(userKeys.getPrivate(), new TestAuthenticatorEncoder(), testTimestamp);
    String token = testIssuer.buildSignedToken(attestedCheque, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void tooOld() throws Exception {
    AttestedObject attestedCheque = makeAttestedCheque();
    long testTimestamp = 10000;
    Eip712AuthIssuer testIssuer = new TestEip712Authentication(userKeys.getPrivate(), new TestAuthenticatorEncoder(), testTimestamp);
    String token = testIssuer.buildSignedToken(attestedCheque, validatorDomain);
    AttestableObjectDecoder<Cheque> decoder = new ChequeDecoder();
    Eip712AuthValidator newValidator = new Eip712AuthValidator(decoder, encoder, attestorKeys.getPublic(), validatorDomain);
    assertFalse(newValidator.validateRequest(token));
  }

  @Test
  public void incorrectModifiedToken() throws Exception {
    AttestedObject attestedCheque = makeAttestedCheque();
    String token = issuer.buildSignedToken(attestedCheque, validatorDomain);
    byte[] tokenBytes = token.getBytes(StandardCharsets.UTF_8);
    // Flip a bit
    tokenBytes[40] ^= 0x01;
    assertFalse(validator.validateRequest(new String(tokenBytes, StandardCharsets.UTF_8)));
  }

  @Test
  public void incorrectDomain() throws Exception {
    AttestedObject attestedCheque = makeAttestedCheque();
    // Extra a in domain
    String token = issuer.buildSignedToken(attestedCheque, "http://www.hotelbogotaa.com");
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void invalidDomainVerifier() {
    AttestableObjectDecoder<Cheque> decoder = new ChequeDecoder();
    assertThrows( RuntimeException.class, () -> {
      new Eip712AuthValidator(decoder, encoder, attestorKeys.getPublic(), "www.noHttpPrefix.com");
    });
  }

  @Test
  public void invalidDomainIssuer() {
    AttestedObject attestedCheque = makeAttestedCheque();
    assertThrows( RuntimeException.class, () -> {
      AuthenticatorEncoder authenticator = new AuthenticatorEncoder(1, rand);
      Eip712AuthIssuer issuer = new Eip712AuthIssuer(userKeys.getPrivate(), authenticator);
      issuer.buildSignedToken(attestedCheque, "www.noHttpPrefix.com");
    });
  }

  @Test
  public void invalidVersion() throws Exception {
    AttestedObject attestedCheque = makeAttestedCheque();
    Eip712AuthIssuer testIssuer = new Eip712AuthIssuer(userKeys.getPrivate(), new TestAuthenticatorEncoder("2.2", 1));
    String token = testIssuer.buildSignedToken(attestedCheque, validatorDomain);
    assertFalse(validator.validateRequest(token));
  }

  @Test
  public void consistentSalt() {
    String salt = encoder.getSalt();
    assertNotNull(salt);
    String otherSalt = encoder.getSalt();
    assertEquals(salt, otherSalt);
  }

  private class TestEip712Authentication extends Eip712AuthIssuer {
    private final Timestamp testTimestamp;

    public TestEip712Authentication(AsymmetricKeyParameter signingKey, AuthenticatorEncoder authenticator, long testTimestamp) {
      super(signingKey, authenticator);
      this.testTimestamp = new Timestamp(testTimestamp);
    }

    @Override
    public String buildSignedToken(AttestedObject attestedObject, String webDomain) throws JsonProcessingException {
      String encodedObject = URLUtility.encodeData(attestedObject.getDerEncoding());
      FullEip712InternalData auth = new FullEip712InternalData(
          encoder.getUsageValue(), encodedObject, testTimestamp);
      return buildSignedTokenFromJsonObject(auth, webDomain);
    }
  }

  private class TestAuthenticatorEncoder extends AuthenticatorEncoder {
    private String protoVersion = super.getProtocolVersion();

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
