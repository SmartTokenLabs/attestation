package org.tokenscript.eip712;

import com.alphawallet.token.entity.EthereumTypedMessage;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Domain;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Message;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import com.alphawallet.token.web.Ethereum.web3j.StructuredDataEncoder;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.SignatureUtility;

public class Eip712Validator extends Eip712Common {
  private static final Logger logger = LogManager.getLogger(Eip712Validator.class);

  protected final String domain;

  public Eip712Validator(String domain, Eip712Encoder encoder) {
    super(encoder);
    if (!Eip712Common.isDomainValid(domain)) {
      throw new IllegalArgumentException("Issuer domain is not a valid domain");
    }
    this.domain = domain;
  }

  /**
   * Retrieve the underlying JSON object
   */
  public <T extends Eip712InternalData> T retrieveUnderlyingJson(String signedJsonInput, Class<T> type) {
    try {
      Eip712ExternalData allData = mapper.readValue(signedJsonInput, Eip712ExternalData.class);
      // Use StructuredDataEncoder to ensure that the data structure gets verified
      StructuredDataEncoder encoder = new StructuredDataEncoder(allData.getJsonSigned());
      return mapper.convertValue(encoder.jsonMessageObject.getMessage(), type);
    } catch (Exception e) {
      throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Could not decode json", e));
    }
  }

  public boolean validateDomain(String signedJsonInput) {
    try {
      EIP712Domain domainToCheck = restoreDomain(signedJsonInput);
      if (!domainToCheck.getName().equals(domain)) {
        logger.error("Domain name is not valid");
        return false;
      }
      if (!domainToCheck.getVersion().equals(encoder.getProtocolVersion())) {
        logger.error("Protocol version is wrong");
        return false;
      }
      if (!Objects.equals(domainToCheck.getChainId(), encoder.getChainId())) {
        logger.error("Chain ID is wrong");
        return false;
      }
      if (!Objects.equals(domainToCheck.getVerifyingContract(), encoder.getVerifyingContract())) {
        logger.error("Verifying contract is wrong");
        return false;
      }
      if (!Objects.equals(domainToCheck.getSalt(), encoder.getSalt())) {
        logger.error("Salt is wrong");
        return false;
      }
      return true;
    }
    catch (Exception e) {
      logger.error("Could not restore domain from json");
      throw ExceptionUtil.makeRuntimeException(logger, "Could not restore domain from json", e);
    }
  }

  public <T extends FullEip712InternalData> boolean verifySignature(String signedJsonInput, String pkAddress, Class<T> type) {
    try {
      AsymmetricKeyParameter candidateKey = retrieveUserPublicKey(signedJsonInput, type);
      if (!SignatureUtility.verifyKeyAgainstAddress(candidateKey, pkAddress)) {
        logger.error("Could not verify signature");
        return false;
      }
    } catch (IllegalArgumentException e) {
      logger.error("Could not recover the user key");
      return false;
    }
    return true;
  }

  public <T extends FullEip712InternalData> ECPublicKeyParameters retrieveUserPublicKey(String signedJsonInput, Class<T> type) {
    try {
      // substring(2) is needed to remove the "0x" prefix
      byte[] rawSignature = Hex.decode(getSignatureFromJson(signedJsonInput).substring(2));
      String actuallySignedJson = restoreSignableJson(signedJsonInput, type);
      EthereumTypedMessage ethereumMessage = new EthereumTypedMessage(actuallySignedJson,null, 0, cryptoFunctions);
      byte[] messageSigned = ethereumMessage.getPrehash();
      return SignatureUtility.recoverEthPublicKeyFromSignature(messageSigned, rawSignature);
    } catch (Exception e) {
      throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Could not recover a valid key"));
    }
  }

  public <T extends FullEip712InternalData> String restoreSignableJson(String signedJsonInput, Class<T> type) throws Exception {
    T fullInternalData = retrieveUnderlyingJson(signedJsonInput, type);
    Eip712ExternalData data = mapper.readValue(signedJsonInput, Eip712ExternalData.class);
    EIP712Domain eip712Domain = restoreDomain(signedJsonInput);
    JsonNode rootNode = mapper.readTree(data.getJsonSigned());
    StructuredData.EIP712Message message = new EIP712Message(getTypes(rootNode), getPrimaryType(rootNode),
        fullInternalData.getSignableVersion(), eip712Domain);
    return mapper.writeValueAsString(message);
  }

  private EIP712Domain restoreDomain(String signedJsonInput) throws Exception {
    Eip712ExternalData data = mapper.readValue(signedJsonInput, Eip712ExternalData.class);
    JsonNode rootNode = mapper.readTree(data.getJsonSigned());
    return mapper.readValue(rootNode.get("domain").toString(), EIP712Domain.class);
  }

  HashMap<String, List<Entry>> getTypes(JsonNode rootOfEip712) throws Exception {
    return mapper.readValue(rootOfEip712.get("types").toString(), HashMap.class);
  }

  String getPrimaryType(JsonNode rootOfEip712) {
    return rootOfEip712.get("primaryType").asText();
  }
}
