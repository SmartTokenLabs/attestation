package org.tokenscript.auth;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.Attestable;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import org.tokenscript.eip712.FullEip712InternalData;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.eip712.Eip712Validator;

/**
 * Class for validating EIP712 tokens containing a useDevconTicket object.
 * The tokens are supposed to be issued by the user for consumption by a third party website.
 */
public class Eip712AuthValidator<T extends Attestable> extends Eip712Validator {
  private final AsymmetricKeyParameter attestorPublicKey;
  private final AttestableObjectDecoder<T> decoder;

  public Eip712AuthValidator(AttestableObjectDecoder<T> decoder, AuthenticatorEncoder authenticator, AsymmetricKeyParameter attestorPublicKey, String domain) {
    this(decoder, authenticator, attestorPublicKey, domain, DEFAULT_TIME_LIMIT_MS);
  }

  public Eip712AuthValidator(AttestableObjectDecoder<T> decoder, AuthenticatorEncoder authenticator, AsymmetricKeyParameter attestorPublicKey, String domain, long acceptableTimeLimit) {
    super(domain, acceptableTimeLimit, authenticator);
    this.attestorPublicKey = attestorPublicKey;
    this.decoder = decoder;
  }

  public boolean validateRequest(String jsonInput) {
    try {
      String eip712Message = retrieveUnderlyingObject(jsonInput);
      FullEip712InternalData auth = mapper.readValue(eip712Message, FullEip712InternalData.class);
      AttestedObject<T> attestedObject = retrieveAttestedObject(auth);
      String signerAddress = SignatureUtility.addressFromKey(attestedObject.getUserPublicKey());

      boolean accept = true;
      accept &= verifySignature(jsonInput, signerAddress, FullEip712InternalData.class);
      accept &= validateAuthentication(auth);
      accept &= validateAttestedObject(attestedObject);
      return accept;
    } catch (Exception e) {
      return false;
    }
  }

  private AttestedObject retrieveAttestedObject(FullEip712InternalData message) {
    byte[] attestedObjectBytes = URLUtility.decodeData(message.getPayload());
    AttestedObject<T> decodedAttestedObject = new AttestedObject<>(attestedObjectBytes, decoder, attestorPublicKey);
    return decodedAttestedObject;
  }

  private boolean validateAuthentication(FullEip712InternalData authentication) {
    boolean accept = true;
    accept &= authentication.getDescription().equals(AuthenticatorEncoder.USAGE_VALUE);
    accept &= verifyTimeStamp(authentication.getTimeStamp());
    return accept;
  }

  private boolean validateAttestedObject(AttestedObject<T> attestedObject) {
    boolean accept = true;
    // Validate useAttestableObject
    accept &= attestedObject.verify();
    accept &= attestedObject.checkValidity();
    return accept;
  }

}
