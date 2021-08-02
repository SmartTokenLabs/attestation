package com.alphawallet.attestation.eip712;

import com.alphawallet.attestation.AttestationRequest;
import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.ExceptionUtil;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.attestation.core.Verifiable;
import com.alphawallet.attestation.eip712.Eip712AttestationRequestEncoder.AttestationRequestInternalData;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.eip712.Eip712Issuer;
import org.tokenscript.eip712.Eip712Validator;
import org.tokenscript.eip712.JsonEncodable;

public class Eip712AttestationRequest extends Eip712Validator implements JsonEncodable, Verifiable, Validateable {
  private static final Logger logger = LogManager.getLogger(Eip712AttestationRequest.class);

  private final AttestationRequest attestationRequest;
  private final AttestationRequestInternalData data;
  private final String jsonEncoding;
  private final AsymmetricKeyParameter publicKey;
  private final long acceptableTimeLimit;

  public Eip712AttestationRequest(String attestorDomain, String identifier,
      AttestationRequest request, AsymmetricKeyParameter signingKey) {
    this(attestorDomain, Timestamp.DEFAULT_TIME_LIMIT_MS, identifier, request, signingKey);
  }

  public Eip712AttestationRequest(String attestorDomain, long acceptableTimeLimit,
      String identifier, AttestationRequest request,
      AsymmetricKeyParameter signingKey) {
    super(attestorDomain, new Eip712AttestationRequestEncoder());
    try {
      this.acceptableTimeLimit = acceptableTimeLimit;
      this.attestationRequest = request;
      this.jsonEncoding = makeToken(identifier, signingKey);
      this.publicKey = retrieveUserPublicKey(jsonEncoding, AttestationRequestInternalData.class);
      this.data = retrieveUnderlyingObject(jsonEncoding, AttestationRequestInternalData.class);
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
    super(attestorDomain, new Eip712AttestationRequestEncoder());
    try {
      this.acceptableTimeLimit = acceptableTimeLimit;
      this.jsonEncoding = jsonEncoding;
      this.publicKey = retrieveUserPublicKey(jsonEncoding, AttestationRequestInternalData.class);
      this.data = retrieveUnderlyingObject(jsonEncoding, AttestationRequestInternalData.class);
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
    Eip712Issuer issuer = new Eip712Issuer<AttestationRequestInternalData>(signingKey, encoder);
    String encodedAttestationRequest = URLUtility.encodeData(attestationRequest.getDerEncoding());
    Timestamp timestamp = Nonce.getTimestamp(attestationRequest.getPok().getNonce());
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
    if (!attestationRequest.verify()) {
      logger.error("Could not verify signature");
      return false;
    }
    return true;
  }

  @Override
  public boolean checkValidity() {
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
    if (!Nonce.validateNonce(getPok().getNonce(),
        SignatureUtility.addressFromKey(publicKey), domain,
        new Timestamp(Timestamp.stringTimestampToLong(data.getTimestamp())-acceptableTimeLimit),
        new Timestamp(Timestamp.stringTimestampToLong(data.getTimestamp())+acceptableTimeLimit))) {
      logger.error("Nonce is not valid");
      return false;
    }
    return true;
  }

}
