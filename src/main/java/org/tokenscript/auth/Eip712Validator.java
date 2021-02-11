package org.tokenscript.auth;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.Attestable;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.token.entity.EthereumTypedMessage;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Domain;
import com.fasterxml.jackson.databind.JsonNode;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.auth.model.ExternalAuthenticationData;
import org.tokenscript.auth.model.InternalAuthenticationData;

/**
 * Class for validating EIP712 tokens containing a useDevconTicket object.
 * The tokens are supposed to be issued by the user for consumption by a third party website.
 */
public class Eip712Validator<T extends Attestable> extends Eip712Common {
  protected final long TIMELIMIT_IN_MS;
  private final AsymmetricKeyParameter attestorPublicKey;
  private final String domain;
  private final AttestableObjectDecoder<T> decoder;

  public Eip712Validator(AttestableObjectDecoder<T> decoder, AsymmetricKeyParameter attestorPublicKey, String domain) {
    this(decoder, attestorPublicKey, domain, 10000);
  }

  public Eip712Validator(AttestableObjectDecoder<T> decoder, AsymmetricKeyParameter attestorPublicKey, String domain,  long acceptableTimeLimit) {
    super();
    if (!isValidDomain(domain)) {
      throw new RuntimeException("Issuer domain is not a valid domain");
    }
    this.domain = domain;
    this.attestorPublicKey = attestorPublicKey;
    this.decoder = decoder;
    this.TIMELIMIT_IN_MS = acceptableTimeLimit;
  }

  public boolean validateRequest(String jsonInput) {
    try {
      ExternalAuthenticationData authenticationData = mapper.readValue(jsonInput, ExternalAuthenticationData.class);
      JsonNode authenticationRootNode = mapper.readTree(authenticationData.getJsonSigned());
      EIP712Domain eip712Domain = mapper.readValue(authenticationRootNode.get("domain").toString(), EIP712Domain.class);
      String eip712Message = authenticationRootNode.get("message").toString();
      InternalAuthenticationData auth = mapper.readValue(eip712Message, InternalAuthenticationData.class);
      AttestedObject<T> attestedObject = retrieveAttestedObject(auth);

      boolean accept = true;
      accept &= validateDomain(eip712Domain);
      accept &= validateAuthentication(auth);
      accept &= verifySignature(authenticationData, attestedObject.getUserPublicKey());
      accept &= validateAttestedObject(attestedObject);
      return accept;
    } catch (Exception e) {
      return false;
    }
  }

  private AttestedObject retrieveAttestedObject(InternalAuthenticationData message) {
    byte[] attestedObjectBytes = URLUtility.decodeData(message.getPayload());
    AttestedObject<T> decodedAttestedObject = new AttestedObject<>(attestedObjectBytes, decoder, attestorPublicKey);
    return decodedAttestedObject;
  }

  private boolean validateDomain(EIP712Domain domainToCheck) {
    boolean accept = true;
    accept &= domainToCheck.getName().equals(domain);
    accept &= domainToCheck.getVersion().equals(Eip712Authenticator.PROTOCOL_VERSION);
    return accept;
  }

  private boolean validateAuthentication(InternalAuthenticationData authentication) {
    try {
      boolean accept = true;
      accept &= authentication.getDescription().equals(Eip712Authenticator.USAGE_VALUE);
      accept &= verifyTimeStamp(authentication.getTimeStamp());
      return accept;
    } catch (Exception e) {
      return false;
    }
  }

  private boolean verifySignature(ExternalAuthenticationData data, AsymmetricKeyParameter pk) {
    try {
      // Remove the "0x" prefix
      String prunedSignature = data.getSignatureInHex().substring(2);
      byte[] signature = Hex.decode(prunedSignature);
      EthereumTypedMessage ethereumMessage = new EthereumTypedMessage(data.getJsonSigned(), null, 0, cryptoFunctions);
      byte[] messageSigned = ethereumMessage.getPrehash();
      return SignatureUtility.verifyEthereumSignature(messageSigned, signature, pk);
    } catch (Exception e) {
      return false;
    }
  }

  private boolean validateAttestedObject(AttestedObject<T> attestedObject) {
    boolean accept = true;
    // Validate useAttestableObject
    accept &= attestedObject.verify();
    accept &= attestedObject.checkValidity();
    return accept;
  }

  private boolean verifyTimeStamp(long timestamp) {
    long currentTime = System.currentTimeMillis();
    // Verify timestamp is still valid and not too old
    if ((timestamp < currentTime + TIMELIMIT_IN_MS) &&
        (timestamp > currentTime - TIMELIMIT_IN_MS)) {
      return true;
    }
    return false;
  }

}
