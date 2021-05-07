package org.tokenscript.eip712;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.eip712.Timestamp;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InvalidObjectException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class Eip712Test {
  private static final String testDomain = "http://www.test.com";
  private static final FullEip712InternalData testObject = new FullEip712InternalData("description", "payload", new Timestamp(0));

  private static AsymmetricCipherKeyPair userKeys;
  private static SecureRandom rand;
  private static Eip712Validator validator;
  private static Eip712Issuer issuer;
  private static Eip712Encoder encoder;
  private static ObjectMapper mapper;

  public static void validateEncoding(Eip712Encoder encoder, String signedJson) throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    JsonNode message = mapper.readTree(mapper.readTree(signedJson).get("jsonSigned").asText()).findPath("message");
    // Verify that all elements in the message got encoded
    for (Entry currentEntry : encoder.getTypes().get(encoder.getPrimaryName())) {
      JsonNode node = message.get(currentEntry.getName());
      assertNotNull(node);
      assertTrue(node.asText().length() > 0);
    }
  }
  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    encoder = new TestEncoder();
    validator = new Eip712Validator(testDomain, encoder);
    issuer = new Eip712Issuer(userKeys.getPrivate(), encoder);
    mapper = new ObjectMapper();
  }

  private void checkEquality(FullEip712InternalData computedObject) {
    assertEquals(testObject.getPayload(), computedObject.getPayload());
    assertEquals(testObject.getDescription(), computedObject.getDescription());
    assertEquals(testObject.getTimestamp(), computedObject.getTimestamp());
    assertEquals(testObject.getSignableVersion().getPayload(), computedObject.getSignableVersion().getPayload());
  }

  @Test
  public void testSunshine() throws Exception {
    String token = issuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    checkEquality(validator.retrieveUnderlyingObject(token, FullEip712InternalData.class));
    assertTrue(validator.verifySignature(token, SignatureUtility.addressFromKey(userKeys.getPublic()), FullEip712InternalData.class));
  }

  @Test
  public void referenceEncoding() throws Exception {
    String token = "{\"signatureInHex\":\"0x71d1b3925bcc1482e34f4ae6f5560e27e6a7f3ad48acefb8089f3d450b3b6e225f28d2a73f1b08956e5b75c5ff0552e251492b493849aac8f4a9cd8cc54bee231c\",\"jsonSigned\":\"{\\\"types\\\":{\\\"Test\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"},{\\\"name\\\":\\\"verifyingContract\\\",\\\"type\\\":\\\"address\\\"},{\\\"name\\\":\\\"salt\\\",\\\"type\\\":\\\"bytes32\\\"}]},\\\"primaryType\\\":\\\"Test\\\",\\\"message\\\":{\\\"payload\\\":\\\"payload\\\",\\\"description\\\":\\\"description\\\",\\\"timestamp\\\":\\\"Thu Jan 1 1970 01:00:00 GMT+0100\\\"},\\\"domain\\\":{\\\"name\\\":\\\"http://www.test.com\\\",\\\"version\\\":\\\"1.0\\\",\\\"chainId\\\":1,\\\"verifyingContract\\\":\\\"0x0123456789012345678901234567890123456789\\\",\\\"salt\\\":\\\"0x0000000000000000000000000000000000000000000000000000000000000000\\\"}}\"}";
    String recomputedToken = issuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    assertEquals(token, recomputedToken);
    checkEquality(validator.retrieveUnderlyingObject(token, FullEip712InternalData.class));
    assertTrue(validator.verifySignature(token, SignatureUtility.addressFromKey(userKeys.getPublic()), FullEip712InternalData.class));
  }

  @Test
  public void referenceEncodingOtherOrder() throws Exception {
    String token = "{\"jsonSigned\":\"{  \\\"primaryType\\\":\\\"Test\\\","
        + "\\\"types\\\":{\\\"Test\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"},{\\\"name\\\":\\\"verifyingContract\\\",\\\"type\\\":\\\"address\\\"},{\\\"name\\\":\\\"salt\\\",\\\"type\\\":\\\"bytes32\\\"}]},"
        + "   \\\"message\\\":{\\\"description\\\":\\\"description\\\",  \\\"payload\\\":\\\"payload\\\",  \\\"timestamp\\\":\\\"Thu Jan 1 1970 01:00:00 GMT+0100\\\"},\\\"domain\\\":{\\\"name\\\":\\\"http://www.test.com\\\",\\\"version\\\":\\\"1.0\\\",\\\"chainId\\\":1,\\\"verifyingContract\\\":\\\"0x0123456789012345678901234567890123456789\\\",\\\"salt\\\":\\\"0x0000000000000000000000000000000000000000000000000000000000000000\\\"}}\","
        + "  \"signatureInHex\":\"0x71d1b3925bcc1482e34f4ae6f5560e27e6a7f3ad48acefb8089f3d450b3b6e225f28d2a73f1b08956e5b75c5ff0552e251492b493849aac8f4a9cd8cc54bee231c\" }";
    checkEquality(validator.retrieveUnderlyingObject(token, FullEip712InternalData.class));
    assertTrue(validator.verifySignature(token, SignatureUtility.addressFromKey(userKeys.getPublic()), FullEip712InternalData.class));
  }

  @Test
  public void eipEncoding() throws Exception {
    String json = issuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    validateEncoding(encoder, json);
    String jsonSignable = issuer.buildSignedTokenFromJsonObject(testObject.getSignableVersion(), testDomain);
    validateEncoding(new TestEncoder(), jsonSignable);
  }

  @Test
  public void testNewChainID() throws Exception {
    TestEncoder localTestEncoder = new TestEncoder("1", 42);
    Eip712Issuer localIssuer = new Eip712Issuer(userKeys.getPrivate(), localTestEncoder);
    String token = localIssuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    String otherToken = localIssuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    assertEquals(token, otherToken);
    Eip712Validator localValidator = new Eip712Validator(testDomain, localTestEncoder);
    checkEquality(localValidator.retrieveUnderlyingObject(token, FullEip712InternalData.class));
    assertTrue(localValidator.verifySignature(token, SignatureUtility.addressFromKey(userKeys.getPublic()), FullEip712InternalData.class));
    // Other chain ID in global validator
    assertFalse(validator.verifySignature(token, SignatureUtility.addressFromKey(userKeys.getPublic()), FullEip712InternalData.class));
  }

  @Test
  public void testConsistency() throws Exception {
    String token = issuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    String newToken = issuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    assertEquals(token, newToken);
  }

  @Test
  public void nullInput() {
    assertThrows( IllegalArgumentException.class, () -> validator.retrieveUnderlyingObject(null, FullEip712InternalData.class));
  }

  @Test
  public void testDifferenceWithDifferentChainIds() throws Exception {
    String token = issuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    TestEncoder localTestEncoder = new TestEncoder("1.0", 42);
    Eip712Issuer localIssuer = new Eip712Issuer(userKeys.getPrivate(), localTestEncoder);
    String newToken = localIssuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    assertFalse(token.equals(newToken));
  }

  @Test
  public void wrongSignature() throws Exception {
    AsymmetricCipherKeyPair newKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    Eip712Issuer newIssuer = new Eip712Issuer(newKeys.getPrivate(), encoder);
    String token = newIssuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    checkEquality(validator.retrieveUnderlyingObject(token, FullEip712InternalData.class));
    assertTrue(validator.verifySignature(token, SignatureUtility.addressFromKey(newKeys.getPublic()), FullEip712InternalData.class));
    assertFalse(validator.verifySignature(token, SignatureUtility.addressFromKey(userKeys.getPublic()), FullEip712InternalData.class));
  }

  @Test
  public void incorrectModifiedToken() throws Exception {
    String token = issuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    byte[] tokenBytes = token.getBytes(StandardCharsets.UTF_8);
    // Flip a bit
    tokenBytes[0] ^= 0x01;
    assertFalse(validator.verifySignature(new String(tokenBytes, StandardCharsets.UTF_8), SignatureUtility.addressFromKey(userKeys.getPublic()), FullEip712InternalData.class));
    assertThrows(IllegalArgumentException.class, () -> validator.retrieveUnderlyingObject(new String(tokenBytes, StandardCharsets.UTF_8), FullEip712InternalData.class));
  }

  @Test
  public void incorrectDomain() throws Exception {
    String token = issuer.buildSignedTokenFromJsonObject(testObject, "http://www.not-test.com");
    Eip712ExternalData data = mapper.readValue(token, Eip712ExternalData.class);
    JsonNode rootNode = mapper.readTree(data.getJsonSigned());
    assertThrows(InvalidObjectException.class, () -> validator.getDomainFromJson(rootNode));
  }

  @Test
  public void invalidDomainIssuer() {
    assertThrows(IllegalArgumentException.class, () -> issuer.buildSignedTokenFromJsonObject(testObject, "www.noHttpPrefix.com"));
  }

  @Test
  public void invalidDomainVerifier() {
    assertThrows(IllegalArgumentException.class, () -> new Eip712Validator("www.noHttpPrefix.com", encoder));
  }

  @Test
  public void invalidVersionIssuer() throws Exception {
    Eip712Issuer newIssuer = new Eip712Issuer(userKeys.getPrivate(), new TestEncoder("2.0", 1));
    String token = newIssuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    Eip712ExternalData data = mapper.readValue(token, Eip712ExternalData.class);
    JsonNode rootNode = mapper.readTree(data.getJsonSigned());
    assertThrows(InvalidObjectException.class, () -> validator.getDomainFromJson(rootNode));
  }

  @Test
  public void invalidVersionValidator() throws Exception {
    Eip712Validator newValidator = new Eip712Validator(testDomain, new TestEncoder("2.0", 1));
    String token = issuer.buildSignedTokenFromJsonObject(testObject, testDomain);
    Eip712ExternalData data = mapper.readValue(token, Eip712ExternalData.class);
    JsonNode rootNode = mapper.readTree(data.getJsonSigned());
    assertThrows(InvalidObjectException.class, () -> newValidator.getDomainFromJson(rootNode));
  }


  @Test
  public void invalidAddressInEncoder() {
    Exception e = assertThrows(RuntimeException.class, () -> new TestEncoder("1", 1, "0x0000incorrectAddress0000"));
    assertEquals("Not a valid address given as verifying contract", e.getMessage());
  }

  @Test
  public void invalidStringTimestamp() {
    // does not contain ms
    Exception e = assertThrows(RuntimeException.class, () -> Timestamp.stringTimestampToLong("1987.01.01 at 01:00:00 CET"));
    assertEquals("Could not decode timestamp", e.getMessage());
  }

  @Test
  public void tooLongSalt() {
    byte[] salt = new byte[33];
    Exception e = assertThrows(RuntimeException.class, () -> new TestEncoder("0.1", 1, "0x0123456789012345678901234567890123456789", salt));
    assertEquals("Salt must be 32 bytes", e.getMessage());
  }

  @Test
  public void tooShortSalt() {
    byte[] salt = new byte[31];
    Exception e = assertThrows(RuntimeException.class, () -> new TestEncoder("0.1", 1, "0x0123456789012345678901234567890123456789", salt));
    assertEquals("Salt must be 32 bytes", e.getMessage());
  }

  private static class TestEncoder extends Eip712Encoder {

    private static final String protocolVersion = "1.0";

    public TestEncoder() {
      super("Test", protocolVersion, "Test", 1L, "0x0123456789012345678901234567890123456789",
          new byte[32]);
    }
    public TestEncoder(String protocolVersion, long chainId) {
      super("Test", protocolVersion, "Test", chainId, "0x0123456789012345678901234567890123456789",
          new byte[32]);
    }
    public TestEncoder(String protocolVersion, long chainId, String contract) {
      super("Test", protocolVersion, "Test", chainId, contract, new byte[32]);
    }
    public TestEncoder(String protocolVersion, long chainId, String contract, byte[] salt) {
      super("Test", protocolVersion, "Test", chainId, contract, salt);
    }

    @Override
    public HashMap<String, List<Entry>> getTypes() {
      return getDefaultTypes();
    }
  }

}
