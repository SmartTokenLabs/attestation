package org.tokenscript.eip712;

import com.alphawallet.token.entity.EthereumTypedMessage;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Domain;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Message;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.attestation.core.SignatureUtility;

public class Eip712Signer<T extends FullEip712InternalData> extends Eip712Common {
  protected final AsymmetricKeyParameter signingKey;

  public Eip712Signer(AsymmetricKeyParameter signingKey, Eip712Encoder encoder) {
    super(encoder);
    this.signingKey = signingKey;
  }

  public String buildSignedTokenFromJsonObject(T jsonEncodableObject, String webDomain) throws JsonProcessingException  {
    if (!Eip712Common.isDomainValid(webDomain)) {
      throw new IllegalArgumentException("Invalid domain");
    }
    byte[] processedMessage = buildTokenToBeSigned(jsonEncodableObject, webDomain);
    // Include the full version of the JSON in the external data
    Eip712ExternalData data = new Eip712ExternalData(signEIP712Message(processedMessage),
        getEncodedObject(jsonEncodableObject, webDomain));
    return mapper.writeValueAsString(data);
  }

  public byte[] buildTokenToBeSigned(T jsonEncodableObject, String webDomain) throws JsonProcessingException {
    // Construct a more compact version of the JSON that is more suited for human reading than the full data
    String jsonToSign = getEncodedObject(jsonEncodableObject.getSignableVersion(), webDomain);
    EthereumTypedMessage ethereumMessage = new EthereumTypedMessage(jsonToSign, null, 0,
        cryptoFunctions);
    return ethereumMessage.getPrehash();
  }

  String getEncodedObject(Eip712InternalData jsonEncodableObject, String webDomain) throws JsonProcessingException {
    StructuredData.EIP712Domain domain = new EIP712Domain(webDomain, encoder.getProtocolVersion(),
        encoder.getChainId(), encoder.getVerifyingContract(), encoder.getSalt());
    StructuredData.EIP712Message message = new EIP712Message(encoder.getTypes(), encoder.getPrimaryName(),
        jsonEncodableObject, domain);
    return mapper.writeValueAsString(message);
  }

  private String signEIP712Message(byte[] msg) {
    byte[] rawSignature = SignatureUtility.signWithEthereum(msg, signingKey);
    return "0x" + new String(Hex.encode(rawSignature), StandardCharsets.UTF_8);
  }
}
