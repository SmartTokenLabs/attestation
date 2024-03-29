package org.tokenscript.attestation.eip712;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.AttestationRequest;
import org.tokenscript.attestation.FullProofOfExponent;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.Timestamp;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.URLUtility;
import org.tokenscript.attestation.core.Validateable;
import org.tokenscript.attestation.core.Verifiable;
import org.tokenscript.attestation.eip712.Eip712AttestationRequestEncoder.AttestationRequestInternalData;
import org.tokenscript.eip712.*;

public class Eip712AttestationRequest extends Eip712Validator implements JsonEncodable, Verifiable, Validateable {
  private static final Logger logger = LogManager.getLogger(Eip712AttestationRequest.class);

  private final AttestationRequest attestationRequest;
  private final AttestationRequestInternalData data;
  private final String jsonEncoding;
  private final AsymmetricKeyParameter publicKey;
  private final long acceptableTimeLimit;

  /**
   *  For security reasons it should not be possible to accept both legacy and current usage values in the future.
   */
  @Deprecated
  public static Eip712AttestationRequest decodeAndValidateAttestation(String attestorDomain, String jsonEncoding) {
    Eip712AttestationRequest attestationRequest;
    try {
      // Try with Liscon encoder
      Eip712AttestationRequestEncoder encoder = new Eip712AttestationRequestEncoder(Eip712AttestationRequestEncoder.LISCON_USAGE_VALUE);
      attestationRequest = new Eip712AttestationRequest(attestorDomain,
          Timestamp.DEFAULT_TIME_LIMIT_MS, jsonEncoding, encoder);
      checkAttestRequestVerifiability(attestationRequest);
      checkAttestRequestValidity(attestationRequest);
    } catch (Exception e) {
      // Try with legacy encoding
      Eip712AttestationRequestEncoder encoder = new Eip712AttestationRequestEncoder(Eip712AttestationRequestEncoder.LEGACY_USAGE_VALUE);
      attestationRequest = new Eip712AttestationRequest(attestorDomain,
          Timestamp.DEFAULT_TIME_LIMIT_MS, jsonEncoding, encoder);
      checkAttestRequestVerifiability(attestationRequest);
      checkAttestRequestValidity(attestationRequest);
    }
    return attestationRequest;
  }

  public Eip712AttestationRequest(String attestorDomain, String identifier,
      AttestationRequest request, AsymmetricKeyParameter signingKey) {
    this(attestorDomain, Timestamp.DEFAULT_TIME_LIMIT_MS, identifier, request, signingKey);
  }

  public Eip712AttestationRequest(String attestorDomain, long acceptableTimeLimit,
      String identifier, AttestationRequest request,
      AsymmetricKeyParameter signingKey) {
    this(attestorDomain, acceptableTimeLimit, identifier, request, signingKey, new Eip712AttestationRequestEncoder(Eip712AttestationRequestEncoder.LISCON_USAGE_VALUE));
  }

  public Eip712AttestationRequest(String attestorDomain, long acceptableTimeLimit,
      String identifier, AttestationRequest request,
      AsymmetricKeyParameter signingKey, Eip712AttestationRequestEncoder encoder) {
    super(attestorDomain, encoder);
    try {
      this.acceptableTimeLimit = acceptableTimeLimit;
      this.attestationRequest = request;
      this.jsonEncoding = makeToken(identifier, signingKey);
      this.publicKey = retrieveUserPublicKey(jsonEncoding, AttestationRequestInternalData.class);
      this.data = retrieveUnderlyingJson(jsonEncoding, AttestationRequestInternalData.class);
    } catch (Exception e ) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not encode object"));
    }
    constructorCheck();
  }

  public Eip712AttestationRequest(String attestorDomain, String jsonEncoding) {
    this(attestorDomain, Timestamp.DEFAULT_TIME_LIMIT_MS, jsonEncoding);
  }

  public Eip712AttestationRequest(String attestorDomain, long acceptableTimeLimit,
      String jsonEncoding) {
    this(attestorDomain, acceptableTimeLimit, jsonEncoding, new Eip712AttestationRequestEncoder(Eip712AttestationRequestEncoder.LISCON_USAGE_VALUE));
  }

  public Eip712AttestationRequest(String attestorDomain, long acceptableTimeLimit,
      String jsonEncoding, Eip712AttestationRequestEncoder encoder) {
    super(attestorDomain, encoder);
    try {
      this.acceptableTimeLimit = acceptableTimeLimit;
      this.jsonEncoding = jsonEncoding;
      this.publicKey = retrieveUserPublicKey(jsonEncoding, AttestationRequestInternalData.class);
      this.data = retrieveUnderlyingJson(jsonEncoding, AttestationRequestInternalData.class);
      this.attestationRequest = new AttestationRequest(URLUtility.decodeData(data.getPayload()));
    } catch (Exception e ) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not decode object"));
    }
    constructorCheck();
  }

  void constructorCheck() throws IllegalArgumentException {
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not verify Eip712 AttestationRequest"));
    }
  }

  String makeToken(String identifier, AsymmetricKeyParameter signingKey) throws JsonProcessingException {
    Eip712Signer issuer = new Eip712Signer<AttestationRequestInternalData>(signingKey, encoder);
    String encodedAttestationRequest = URLUtility.encodeData(attestationRequest.getDerEncoding());
    Timestamp timestamp = Nonce.getTimestamp(attestationRequest.getPok().getUnpredictableNumber());
    AttestationRequestInternalData data = new AttestationRequestInternalData(
        encoder.getUsageValue(), identifier, encodedAttestationRequest, timestamp);
    return issuer.buildSignedTokenFromJsonObject(data, domain);
  }

  public String getIdentifier() {
    return data.getIdentifier();
  }

  public AsymmetricKeyParameter getUserPublicKey() {
    return publicKey;
  }

  public AttestationType getType() {
    return attestationRequest.getType();
  }

  public FullProofOfExponent getPok() {
    return attestationRequest.getPok();
  }

  @Override
  public String getJsonEncoding() {
    return jsonEncoding;
  }

  @Override
  public boolean verify() {
    // Notice that the signature cannot be validated against anything since it is used to simply retrieve the address
    if (!attestationRequest.verify()) {
      logger.error("Could not verify proof");
      return false;
    }
    return true;
  }

  @Override
  public boolean checkValidity() {
    if (!validateDomain(jsonEncoding)) {
      logger.error("Domain invalid");
      return false;
    }
    if (!data.getDescription().equals(encoder.getUsageValue())){
      logger.error("Description field is incorrect");
      return false;
    }
    Timestamp timestamp = new Timestamp(data.getTimestamp());
    timestamp.setValidity(acceptableTimeLimit);
    if (!timestamp.validateTimestamp()) {
      logger.error("Timestamp is not valid");
      return false;
    }
    if (!Nonce.validateNonce(getPok().getUnpredictableNumber(),
        SignatureUtility.addressFromKey(publicKey), domain,
        new Timestamp(Timestamp.stringTimestampToLong(data.getTimestamp())-acceptableTimeLimit),
        new Timestamp(Timestamp.stringTimestampToLong(data.getTimestamp())+acceptableTimeLimit))) {
      logger.error("Nonce is not valid");
      return false;
    }
    return true;
  }

}
