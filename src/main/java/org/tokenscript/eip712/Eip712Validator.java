package org.tokenscript.eip712;

import com.alphawallet.attestation.ValidationTools;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.token.entity.EthereumTypedMessage;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Domain;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Message;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import com.alphawallet.token.web.Ethereum.web3j.StructuredDataEncoder;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.InvalidObjectException;
import java.text.ParseException;
import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;

public class Eip712Validator extends Eip712Common {
  public static final int DEFAULT_TIME_LIMIT_MS = 10000;

  protected final String domain;
  protected final long acceptableTimeLimitMs;

  public Eip712Validator(String domain, Eip712Encoder encoder) {
    this(domain, DEFAULT_TIME_LIMIT_MS, encoder);
  }

  public Eip712Validator(String domain, long acceptableTimeLimitMs, Eip712Encoder encoder) {
    super(encoder);
    this.acceptableTimeLimitMs = acceptableTimeLimitMs;
    if (!Eip712Common.isDomainValid(domain)) {
      throw new IllegalArgumentException("Issuer domain is not a valid domain");
    }
    this.domain = domain;
  }

  /**
   * Retrieve the underlying JSON object
   */
  public <T extends Eip712InternalData> T retrieveUnderlyingObject(String signedJsonInput, Class<T> type) throws InvalidObjectException {
    try {
      Eip712ExternalData allData = mapper.readValue(signedJsonInput, Eip712ExternalData.class);
      // Use StructuredDataEncoder to ensure that the data structure gets verified
      StructuredDataEncoder encoder = new StructuredDataEncoder(allData.getJsonSigned());
      return mapper.convertValue(encoder.jsonMessageObject.getMessage(), type);
    } catch (Exception e) {
      throw new InvalidObjectException(e.getMessage());
    }
  }

  private boolean validateDomain(EIP712Domain domainToCheck) {
    boolean accept = true;
    accept &= domainToCheck.getName().equals(domain);
    accept &= domainToCheck.getVersion().equals(encoder.getProtocolVersion());
    accept &= Objects.equals(domainToCheck.getChainId(), encoder.getChainId());
    accept &= Objects.equals(domainToCheck.getVerifyingContract(), encoder.getVerifyingContract());
    accept &= Objects.equals(domainToCheck.getSalt(), encoder.getSalt());
    return accept;
  }

  public boolean verifyTimeStamp(String timestamp) {
    try {
      long timestampInMs = encoder.TIMESTAMP_FORMAT.parse(timestamp).getTime();
      long currentTime = Clock.systemUTC().millis();
      return ValidationTools.validateTimestamp(timestampInMs, currentTime, acceptableTimeLimitMs);
    } catch (ParseException e) {
      return false;
    }
  }

  public <T extends FullEip712InternalData> boolean verifySignature(String signedJsonInput, String pkAddress, Class<T> type) {
    try {
      AsymmetricKeyParameter candidateKey = retrieveUserPublicKey(signedJsonInput, type);
      return SignatureUtility.verifyKeyAgainstAddress(candidateKey, pkAddress);
    } catch (InvalidObjectException e) {
      return false;
    }
  }

  public <T extends FullEip712InternalData> ECPublicKeyParameters retrieveUserPublicKey(String signedJsonInput, Class<T> type) throws InvalidObjectException {
    try {
      byte[] signature = getSignatureFromJson(signedJsonInput);
      String actuallySignedJson = restoreSignableJson(signedJsonInput, type);
      EthereumTypedMessage ethereumMessage = new EthereumTypedMessage(actuallySignedJson,null, 0, cryptoFunctions);
      byte[] messageSigned = ethereumMessage.getPrehash();
      return SignatureUtility.recoverEthPublicKeyFromSignature(messageSigned, signature);
    } catch (Exception e) {
      throw new InvalidObjectException("Could not recover a valid key");
    }
  }

  byte[] getSignatureFromJson(String signedJsonInput) throws Exception {
    Eip712ExternalData data = mapper.readValue(signedJsonInput, Eip712ExternalData.class);
    // Remove the "0x" prefix
    String prunedSignature = data.getSignatureInHex().substring(2);
    return Hex.decode(prunedSignature);
  }

  <T extends FullEip712InternalData> String restoreSignableJson(String signedJsonInput, Class<T> type) throws Exception {
    T fullInternalData = retrieveUnderlyingObject(signedJsonInput, type);
    Eip712ExternalData data = mapper.readValue(signedJsonInput, Eip712ExternalData.class);
    JsonNode rootNode = mapper.readTree(data.getJsonSigned());
    EIP712Domain eip712Domain = getDomainFromJson(rootNode);
    StructuredData.EIP712Message message = new EIP712Message(getTypes(rootNode), getPrimaryType(rootNode),
        fullInternalData.getSignableVersion(), eip712Domain);
    return mapper.writeValueAsString(message);
  }

  HashMap<String, List<Entry>> getTypes(JsonNode rootOfEip712) throws Exception {
    return mapper.readValue(rootOfEip712.get("types").toString(), HashMap.class);
  }

  String getPrimaryType(JsonNode rootOfEip712) {
    return rootOfEip712.get("primaryType").asText();
  }

  /**
   * Retrieve and validate the domain
   */
  EIP712Domain getDomainFromJson(JsonNode rootOfEip712) throws Exception {
    EIP712Domain eip712Domain = mapper.readValue(rootOfEip712.get("domain").toString(), EIP712Domain.class);
    if (!validateDomain(eip712Domain)) {
      throw new InvalidObjectException("Could not verify message");
    }
    return eip712Domain;
  }
}
