package org.tokenscript.auth;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.Attestable;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.eip712.Nonce;
import com.alphawallet.attestation.eip712.Timestamp;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.eip712.Eip712Validator;
import org.tokenscript.eip712.FullEip712InternalData;

/**
 * Class for validating EIP712 tokens containing a useDevconTicket object.
 * The tokens are supposed to be issued by the user for consumption by a third party website.
 */
public class Eip712AuthValidator<T extends Attestable> extends Eip712Validator {
  private static final Logger logger = LogManager.getLogger(Eip712AuthValidator.class);
  private final AsymmetricKeyParameter attestorPublicKey;
  private final AttestableObjectDecoder<T> decoder;
  private final long acceptableTimeLimit;

  public Eip712AuthValidator(AttestableObjectDecoder<T> decoder, AuthenticatorEncoder authenticator, AsymmetricKeyParameter attestorPublicKey, String domain) {
    this(decoder, authenticator, attestorPublicKey, domain, Nonce.DEFAULT_NONCE_TIME_LIMIT_MS);
  }

  public Eip712AuthValidator(AttestableObjectDecoder<T> decoder, AuthenticatorEncoder authenticator, AsymmetricKeyParameter attestorPublicKey, String domain, long acceptableTimeLimit) {
    super(domain, authenticator);
    this.acceptableTimeLimit = acceptableTimeLimit;
    this.attestorPublicKey = attestorPublicKey;
    this.decoder = decoder;
  }

  public boolean validateRequest(String jsonInput) {
    try {
      FullEip712InternalData auth = retrieveUnderlyingObject(jsonInput, FullEip712InternalData.class);
      AttestedObject<T> attestedObject = retrieveAttestedObject(auth);
      String signerAddress = SignatureUtility.addressFromKey(attestedObject.getUserPublicKey());

      if (!verifySignature(jsonInput, signerAddress, FullEip712InternalData.class)) {
        logger.error("Could not verify signature");
        return false;
      }
      if (!validateAuthentication(auth)) {
        logger.error("Could not validate authentication request data");
        return false;
      }
      if (!validateAttestedObject(attestedObject)) {
        logger.error("Could not validate attested object");
        return false;
      }
    } catch (Exception e) {
      logger.error("Could not decode json request");
      return false;
    }
    return true;
  }

  private AttestedObject retrieveAttestedObject(FullEip712InternalData message) {
    byte[] attestedObjectBytes = URLUtility.decodeData(message.getPayload());
    AttestedObject<T> decodedAttestedObject = new AttestedObject<>(attestedObjectBytes, decoder, attestorPublicKey);
    return decodedAttestedObject;
  }

  private boolean validateAuthentication(FullEip712InternalData authentication) {
    if (!authentication.getDescription().equals(encoder.getUsageValue())) {
      logger.error("Description is incorrect");
      return false;
    }
    Timestamp timestamp = new Timestamp(authentication.getTimestamp());
    timestamp.setValidity(acceptableTimeLimit);
    if (!timestamp.validateTimestamp()) {
      logger.error("Invalid timestamp");
      return false;
    }
    return true;
  }

  private boolean validateAttestedObject(AttestedObject<T> attestedObject) {
    // Validate useAttestableObject
    if (!attestedObject.verify()) {
      logger.error("Could not verify the attested object");
      return false;
    }
    if (!attestedObject.checkValidity()) {
      logger.error("Attested object is not valid");
      return false;
    }
    return true;
  }

}
