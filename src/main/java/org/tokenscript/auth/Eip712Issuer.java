package org.tokenscript.auth;

import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.token.entity.EthereumTypedMessage;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.auth.model.ExternalAuthenticationData;

/**
 * Class for issuing JWT tokens containing a useDevconTicket object.
 * The tokens are supposed to be issued by the user for consumption by a third party website.
 *
 * Thus we are abusing the "normal" three-party setting of JWTs since in our case both the
 * issuer and the subject is the same.
 * We furthermore also misuse the formal format of JWTs since we sign using an Ethereum key, and
 * hence the signature with have "Ethereum Signed Message:" as prefix and use Keccak for hashing.
 */
public class Eip712Issuer extends Eip712Common {
  private final Eip712Authenticator authenticator;
  private final AsymmetricCipherKeyPair signingKeys;

  public Eip712Issuer(AsymmetricCipherKeyPair signingKeys) {
    this(signingKeys, new Eip712Authenticator(new SecureRandom()));
  }

  public Eip712Issuer(AsymmetricCipherKeyPair signingKeys, Eip712Authenticator authenticator) {
    super();
    this.authenticator = authenticator;
    this.signingKeys = signingKeys;
  }

  public String makeToken(AttestedObject attestedObject, String webDomain) {
    return makeToken(attestedObject, webDomain, 0);
  }
  public String makeToken(AttestedObject attestedObject, String webDomain, int chainID) {
    if (!isValidDomain(webDomain)) {
      throw new IllegalArgumentException("Invalid domain");
    }
    String encodedObject = URLUtility.encodeData(attestedObject.getDerEncoding());
    String jsonToSign = authenticator.jsonEncode(encodedObject, webDomain);
    EthereumTypedMessage ethereumMessage = new EthereumTypedMessage(jsonToSign, null, 0,
        cryptoFunctions);
    String signatureInHex = signEIP712Message(ethereumMessage, chainID);
    return buildJsonToken(jsonToSign, signatureInHex, chainID);
  }

  private String signEIP712Message(EthereumTypedMessage msg, int chainID) {
    byte[] signature = SignatureUtility.signWithEthereum(msg.getPrehash(), chainID, signingKeys);
    return "0x" + new String(Hex.encode(signature), StandardCharsets.UTF_8);
  }

  public String buildJsonToken(String jsonSigned, String signatureInHex, int chainID)   {
    try {
      ExternalAuthenticationData data = new ExternalAuthenticationData(signatureInHex, JSON_RPC_VER, chainID, jsonSigned);
      return mapper.writeValueAsString(data);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

}
