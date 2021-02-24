package org.tokenscript.eip712;

import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.token.entity.EthereumTypedMessage;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Domain;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Message;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.encoders.Hex;

public class Eip712Issuer extends Eip712Common {
  protected final AsymmetricCipherKeyPair signingKeys;
  protected final Eip712Encoder encoder;

  public Eip712Issuer(AsymmetricCipherKeyPair signingKeys, Eip712Encoder encoder) {
    super();
    this.signingKeys = signingKeys;
    this.encoder = encoder;
  }

  public String buildSignedTokenFromJsonObject(Object jsonEncodableObject, String webDomain, int chainID) {
    if (!Eip712Common.isDomainValid(webDomain)) {
      throw new IllegalArgumentException("Invalid domain");
    }
    try {
      String jsonToSign = getEncodedObject(jsonEncodableObject, webDomain);
      EthereumTypedMessage ethereumMessage = new EthereumTypedMessage(jsonToSign, null, 0,
          cryptoFunctions);
      String signatureInHex = signEIP712Message(ethereumMessage, chainID);
      Eip712Data data = new Eip712Data(signatureInHex, JSON_RPC_VER, chainID, jsonToSign);
      return mapper.writeValueAsString(data);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private String getEncodedObject(Object jsonEncodableObject, String webDomain) throws Exception {
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
