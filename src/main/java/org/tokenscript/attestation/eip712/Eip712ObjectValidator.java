package org.tokenscript.attestation.eip712;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.tokenscript.attestation.AttestedKeyObject;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.Timestamp;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.URLUtility;
import org.tokenscript.eip712.Eip712Encoder;
import org.tokenscript.eip712.Eip712Validator;
import org.tokenscript.eip712.FullEip712InternalData;

/**
 * Class for validating EIP712 tokens containing any ASNEncodable object.
 */
public class Eip712ObjectValidator<T extends AttestedKeyObject> extends Eip712Validator {
  private static final Logger logger = LogManager.getLogger(Eip712ObjectValidator.class);
  private final ObjectDecoder<T> decoder;
  private final long acceptableTimeLimit;

  public Eip712ObjectValidator(ObjectDecoder<T> decoder, Eip712Encoder authenticator,
      String domain) {
    this(decoder, authenticator, domain, Nonce.DEFAULT_NONCE_TIME_LIMIT_MS);
  }

  public Eip712ObjectValidator(ObjectDecoder<T> decoder, Eip712Encoder authenticator,
      String domain, long acceptableTimeLimit) {
    super(domain, authenticator);
    this.acceptableTimeLimit = acceptableTimeLimit;
    this.decoder = decoder;
  }

  public boolean validateRequest(String jsonInput) {
    try {
      FullEip712InternalData eip712InternalData = retrieveUnderlyingJson(jsonInput, FullEip712InternalData.class);
      T attestedObject = retrieveUnderlyingObject(jsonInput);
      String signerAddress = SignatureUtility.addressFromKey(attestedObject.getAttestedUserKey());

      if (!verifySignature(jsonInput, signerAddress, FullEip712InternalData.class)) {
        logger.error("Could not verify signature");
        return false;
      }
      if (!validateDomain(jsonInput)) {
        logger.error("Could not validate the domain data");
        return false;
      }
      if (!validateEip712InternalData(eip712InternalData)) {
        logger.error("Could not validate authentication request data");
        return false;
      }
      if (!attestedObject.checkValidity()) {
        logger.error("Could not validate attested object");
        return false;
      }
      if (!attestedObject.verify()) {
        logger.error("Could not verify attested object");
        return false;
      }
    } catch (Exception e) {
      logger.error("Could not decode json request");
      return false;
    }
    return true;
  }

  public T retrieveUnderlyingObject(String jsonInput) throws IOException {
    FullEip712InternalData message = retrieveUnderlyingJson(jsonInput, FullEip712InternalData.class);
    byte[] attestedObjectBytes = URLUtility.decodeData(message.getPayload());
    T attestedObject = decoder.decode(attestedObjectBytes);
    return attestedObject;
  }

  private boolean validateEip712InternalData(FullEip712InternalData eip712InternalData) {
    if (!eip712InternalData.getDescription().equals(encoder.getUsageValue())) {
      logger.error("Description is incorrect");
      return false;
    }
    Timestamp timestamp = new Timestamp(eip712InternalData.getTimestamp());
    timestamp.setValidity(acceptableTimeLimit);
    if (!timestamp.validateTimestamp()) {
      logger.error("Invalid timestamp");
      return false;
    }
    return true;
  }

}
