package com.alphawallet.attestation.eip712;

import com.alphawallet.attestation.AttestationRequest;
import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.Nonce;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.attestation.core.Verifiable;
import com.alphawallet.attestation.eip712.Eip712AttestationRequestEncoder.AttestationRequestInternalData;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.time.Clock;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.eip712.Eip712Issuer;
import org.tokenscript.eip712.Eip712Validator;
import org.tokenscript.eip712.JsonEncodable;

public class Eip712AttestationRequest extends Eip712Validator implements JsonEncodable, Verifiable, Validateable {
  public static final int PLACEHOLDER_CHAIN_ID = 0;

  private final AttestationRequest attestationRequest;
  private final AttestationRequestInternalData data;
  private final String jsonEncoding;
  private final AsymmetricKeyParameter publicKey;

  public Eip712AttestationRequest(String attestorDomain, String identifier,
      AttestationRequest request, AsymmetricKeyParameter signingKey, String address) {
    this(attestorDomain, DEFAULT_TIME_LIMIT_MS, identifier, request, signingKey, address);
  }

  public Eip712AttestationRequest(String attestorDomain, long acceptableTimeLimit,
      String identifier, AttestationRequest request,
      AsymmetricKeyParameter signingKey, String address) {
    super(attestorDomain, acceptableTimeLimit, new Eip712AttestationRequestEncoder());
    try {
      this.attestationRequest = request;
      this.jsonEncoding = makeToken(identifier, signingKey, address);
      this.publicKey = retrieveUserPublicKey(jsonEncoding, AttestationRequestInternalData.class);
      this.data = retrieveUnderlyingObject(jsonEncoding, AttestationRequestInternalData.class);
    } catch (Exception e ) {
      throw new IllegalArgumentException("Could not encode object");
    }
    constructorCheck();
  }

  public Eip712AttestationRequest(String attestorDomain, String jsonEncoding) {
    this(attestorDomain, DEFAULT_TIME_LIMIT_MS, jsonEncoding);
  }

  public Eip712AttestationRequest(String attestorDomain, long acceptableTimeLimit, String jsonEncoding) {
    super(attestorDomain, acceptableTimeLimit, new Eip712AttestationRequestEncoder());
    try {
      this.jsonEncoding = jsonEncoding;
      this.publicKey = retrieveUserPublicKey(jsonEncoding, AttestationRequestInternalData.class);
      this.data = retrieveUnderlyingObject(jsonEncoding, AttestationRequestInternalData.class);
      this.attestationRequest = new AttestationRequest(URLUtility.decodeData(data.getPayload()));
    } catch (Exception e ) {
      throw new IllegalArgumentException("Could not decode object");
    }
    constructorCheck();
  }

  void constructorCheck() throws IllegalArgumentException {
    if (!verify()) {
      throw new IllegalArgumentException("Could not verify Eip712 AttestationRequest");
    }
  }

  String makeToken(String identifier, AsymmetricKeyParameter signingKey, String address) throws JsonProcessingException {
    Eip712Issuer issuer = new Eip712Issuer<AttestationRequestInternalData>(signingKey, encoder);
    String encodedAttestationRequest = URLUtility.encodeData(attestationRequest.getDerEncoding());
    AttestationRequestInternalData data = new AttestationRequestInternalData(
        Eip712AttestationRequestEncoder.USAGE_VALUE,
        identifier, address, encodedAttestationRequest, Clock.systemUTC().millis());
    return issuer.buildSignedTokenFromJsonObject(data, domain, PLACEHOLDER_CHAIN_ID);
  }

  public String getIdentifier() {
    return data.getIdentifier();
  }

  public AsymmetricKeyParameter getPublicKey() {
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
      return false;
    }
    if (!verifySignature(jsonEncoding, data.getAddress(), AttestationRequestInternalData.class)) {
      return false;
    }
    return true;
  }

  @Override
  public boolean checkValidity() {
    boolean accept = true;
    accept &= data.getDescription().equals(Eip712AttestationRequestEncoder.USAGE_VALUE);
    accept &= verifyTimeStamp(data.getTimestamp());
    accept &= SignatureUtility.verifyKeyAgainstAddress(publicKey, data.getAddress());
    accept &= Nonce.validateNonce(getPok().getNonce(), getIdentifier(),
        data.getAddress(), domain);
    return accept;
  }

}
