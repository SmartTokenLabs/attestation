package org.tokenscript.auth;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.Attestable;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.auth.AuthenticatorEncoder.InternalAuthenticationData;
import org.tokenscript.eip712.Eip712Common;
import org.tokenscript.eip712.Eip712Validator;

/**
 * Class for validating EIP712 tokens containing a useDevconTicket object.
 * The tokens are supposed to be issued by the user for consumption by a third party website.
 */
public class Eip712AuthValidator<T extends Attestable> extends Eip712Validator {
  protected final long timelimitInMs;
  private final AsymmetricKeyParameter attestorPublicKey;
  private final AttestableObjectDecoder<T> decoder;

  public Eip712AuthValidator(AttestableObjectDecoder<T> decoder, AuthenticatorEncoder authenticator, AsymmetricKeyParameter attestorPublicKey, String domain) {
    this(decoder, authenticator, attestorPublicKey, domain, 10000);
  }

  public Eip712AuthValidator(AttestableObjectDecoder<T> decoder, AuthenticatorEncoder authenticator, AsymmetricKeyParameter attestorPublicKey, String domain,  long acceptableTimeLimit) {
    super(domain, authenticator);
    if (!Eip712Common.isDomainValid(domain)) {
      throw new RuntimeException("Issuer domain is not a valid domain");
    }
    this.attestorPublicKey = attestorPublicKey;
    this.decoder = decoder;
    this.timelimitInMs = acceptableTimeLimit;
  }

  public boolean validateRequest(String jsonInput) {
    try {
      String eip712Message = retrieveUnderlyingObject(jsonInput);
      InternalAuthenticationData auth = mapper.readValue(eip712Message, InternalAuthenticationData.class);
      AttestedObject<T> attestedObject = retrieveAttestedObject(auth);
      String signerAddress = SignatureUtility.addressFromKey(attestedObject.getUserPublicKey());

      boolean accept = true;
      accept &= verifySignature(jsonInput, signerAddress);
      accept &= validateAuthentication(auth);
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

  private boolean validateAuthentication(InternalAuthenticationData authentication) {
    try {
      boolean accept = true;
      accept &= authentication.getDescription().equals(AuthenticatorEncoder.USAGE_VALUE);
      accept &= verifyTimeStamp(authentication.getTimeStamp());
      return accept;
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
    if ((timestamp < currentTime + timelimitInMs) &&
        (timestamp > currentTime - timelimitInMs)) {
      return true;
    }
    return false;
  }

}
