package org.tokenscript.eip712;

import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.token.entity.EthereumTypedMessage;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Domain;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Message;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class Eip712Issuer<T extends FullEip712InternalData> extends Eip712Common {
  protected final AsymmetricKeyParameter signingKey;

  public Eip712Issuer(AsymmetricKeyParameter signingKey, Eip712Encoder encoder) {
    super(encoder);
    this.signingKey = signingKey;
  }

  public String buildSignedTokenFromJsonObject(T jsonEncodableObject, String webDomain) throws JsonProcessingException  {
    if (!Eip712Common.isDomainValid(webDomain)) {
      throw new IllegalArgumentException("Invalid domain");
    }
      // Construct a more compact version of the JSON that is more suited for human reading than the full data
      String jsonToSign = getEncodedObject(jsonEncodableObject.getSignableVersion(), webDomain);
      // Sign this compacted version
      EthereumTypedMessage ethereumMessage = new EthereumTypedMessage(jsonToSign, null, 0,
          cryptoFunctions);
      String signatureInHex = signEIP712Message(ethereumMessage);
      // Include the full version of the JSON in the external data
      Eip712ExternalData data = new Eip712ExternalData(signatureInHex,
          getEncodedObject(jsonEncodableObject, webDomain));
      return mapper.writeValueAsString(data);
  }

  String getEncodedObject(Eip712InternalData jsonEncodableObject, String webDomain) throws JsonProcessingException {
    StructuredData.EIP712Domain domain = new EIP712Domain(webDomain, encoder.getProtocolVersion(),
        encoder.getChainId(), encoder.getVerifyingContract(), encoder.getSalt());
    StructuredData.EIP712Message message = new EIP712Message(encoder.getTypes(), encoder.getPrimaryName(),
        jsonEncodableObject, domain);
    return mapper.writeValueAsString(message);
  }

  private String signEIP712Message(EthereumTypedMessage msg) {
    byte[] signature = SignatureUtility.signWithEthereum(msg.getPrehash(), signingKey);
    return "0x" + new String(Hex.encode(signature), StandardCharsets.UTF_8);
  }
}
