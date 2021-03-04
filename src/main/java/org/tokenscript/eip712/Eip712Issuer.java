package org.tokenscript.eip712;

import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.token.entity.EthereumTypedMessage;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Domain;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Message;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.encoders.Hex;

public class Eip712Issuer extends Eip712Common {
  protected final AsymmetricCipherKeyPair signingKeys;

  public Eip712Issuer(AsymmetricCipherKeyPair signingKeys, Eip712Encoder encoder) {
    super(encoder);
    this.signingKeys = signingKeys;
  }

  public String buildSignedTokenFromJsonObject(FullEip712InternalData jsonEncodableObject, String webDomain, int chainID) throws JsonProcessingException  {
    if (!Eip712Common.isDomainValid(webDomain)) {
      throw new IllegalArgumentException("Invalid domain");
    }
      // Construct a more compact version of the JSON that is more suited for human reading than the full data
      String jsonToSign = getEncodedObject(new SignableEip712InternalData(jsonEncodableObject), webDomain);
      // Sign this compacted version
      EthereumTypedMessage ethereumMessage = new EthereumTypedMessage(jsonToSign, null, 0,
          cryptoFunctions);
      String signatureInHex = signEIP712Message(ethereumMessage, chainID);
      // Include the full version of the JSON in the external data
      Eip712ExternalData data = new Eip712ExternalData(signatureInHex, JSON_RPC_VER, chainID, getEncodedObject(jsonEncodableObject, webDomain));
      return mapper.writeValueAsString(data);
  }

  String getEncodedObject(Eip712InternalData jsonEncodableObject, String webDomain) throws JsonProcessingException {
    StructuredData.EIP712Domain domain = new EIP712Domain(webDomain, encoder.getProtocolVersion(),
        null, null, encoder.getSalt());
    StructuredData.EIP712Message message = new EIP712Message(encoder.getTypes(), encoder.getPrimaryName(),
        jsonEncodableObject, domain);
    return mapper.writeValueAsString(message);
  }

  private String signEIP712Message(EthereumTypedMessage msg, int chainID) {
    byte[] signature = SignatureUtility.signWithEthereum(msg.getPrehash(), chainID, signingKeys);
    return "0x" + new String(Hex.encode(signature), StandardCharsets.UTF_8);
  }
}
