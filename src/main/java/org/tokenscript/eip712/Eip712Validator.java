package org.tokenscript.eip712;

import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.token.entity.EthereumTypedMessage;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Domain;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Message;
import com.alphawallet.token.web.Ethereum.web3j.StructuredDataEncoder;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.InvalidObjectException;
import java.time.Clock;
import java.util.Date;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;

public class Eip712Validator extends Eip712Common {
  public static final int DEFAULT_TIME_LIMIT_MS = 100000;

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
    accept &= domainToCheck.getChainId() == encoder.getChainId();
    return accept;
  }

  public boolean verifyTimeStamp(String timestamp) {
    try {
      long currentTime = Clock.systemUTC().millis();
      Date currentTimestampWAddedLimit = new Date(currentTime + acceptableTimeLimitMs);
      Date currentTimestampWSubtractedLimit = new Date(currentTime - acceptableTimeLimitMs);
      Date parsedTimestamp = encoder.timestampFormat.parse(timestamp);
      // Verify timestamp is still valid and not too old
      // i.e. parsedTimestamp in ]currentTimestampWSubtractedLimit;  currentTimestampWAddedLimit[
      if (parsedTimestamp.before(currentTimestampWAddedLimit) &&
          parsedTimestamp.after(currentTimestampWSubtractedLimit)) {
        return true;
      }
    } catch (Exception e) {
      return false;
    }
    return false;
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
      EthereumTypedMessage ethereumMessage = new EthereumTypedMessage(actuallySignedJson, null, 0, cryptoFunctions);
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
    EIP712Domain eip712Domain = getDomainFromJson(signedJsonInput);
    StructuredData.EIP712Message message = new EIP712Message(encoder.getTypes(), encoder.getPrimaryName(),
        fullInternalData.getSignableVersion(), eip712Domain);
    return mapper.writeValueAsString(message);
  }

  /**
   * Retrieve and validate the domain
   */
  EIP712Domain getDomainFromJson(String signedJsonInput) throws Exception {
    Eip712ExternalData data = mapper.readValue(signedJsonInput, Eip712ExternalData.class);
    JsonNode rootNode = mapper.readTree(data.getJsonSigned());
    EIP712Domain eip712Domain = mapper.readValue(rootNode.get("domain").toString(), EIP712Domain.class);
    if (!validateDomain(eip712Domain)) {
      throw new InvalidObjectException("Could not verify message");
    }
    return eip712Domain;
  }
}
