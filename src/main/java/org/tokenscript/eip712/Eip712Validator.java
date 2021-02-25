package org.tokenscript.eip712;

import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.token.entity.EthereumTypedMessage;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Domain;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.InvalidObjectException;
import org.bouncycastle.util.encoders.Hex;

public class Eip712Validator extends Eip712Common {
  protected final String domain;
  protected final Eip712Encoder encoder;

  public Eip712Validator(String domain, Eip712Encoder encoder) {
    super();
    if (!Eip712Common.isDomainValid(domain)) {
      throw new IllegalArgumentException("Issuer domain is not a valid domain");
    }
    this.domain = domain;
    this.encoder = encoder;
  }

  /**
   * Retrieve the underlying JSON object and validate protocol version and domain
   */
  public String retrieveUnderlyingObject(String signedJsonInput) throws InvalidObjectException {
    try {
      Eip712Data allData = mapper.readValue(signedJsonInput, Eip712Data.class);
      JsonNode rootNode = mapper.readTree(allData.getJsonSigned());
      EIP712Domain eip712Domain = mapper.readValue(rootNode.get("domain").toString(), EIP712Domain.class);
      if (!validateDomain(eip712Domain)) {
        throw new InvalidObjectException("Could not verify message");
      }
      return rootNode.get("message").toString();
    } catch (Exception e) {
      throw new InvalidObjectException(e.getMessage());
    }
  }

  private boolean validateDomain(EIP712Domain domainToCheck) {
    boolean accept = true;
    accept &= domainToCheck.getName().equals(domain);
    accept &= domainToCheck.getVersion().equals(encoder.getProtocolVersion());
    return accept;
  }

  public boolean verifySignature(String signedJsonInput, String pkAddress) {
    try {
      Eip712Data data = mapper.readValue(signedJsonInput, Eip712Data.class);
      // Remove the "0x" prefix
      String prunedSignature = data.getSignatureInHex().substring(2);
      byte[] signature = Hex.decode(prunedSignature);
      EthereumTypedMessage ethereumMessage = new EthereumTypedMessage(data.getJsonSigned(), null, 0, cryptoFunctions);
      byte[] messageSigned = ethereumMessage.getPrehash();
      return SignatureUtility.verifyEthereumSignature(messageSigned, signature, pkAddress);
    } catch (Exception e) {
      return false;
    }
  }
}
