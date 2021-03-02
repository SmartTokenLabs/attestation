package com.alphawallet.attestation.eip712;

import com.alphawallet.attestation.AttestationRequest;
import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.Nonce;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.attestation.core.Verifiable;
import com.alphawallet.attestation.eip712.Eip712AttestationRequestEncoder.AttestationRequestData;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.eip712.Eip712Issuer;
import org.tokenscript.eip712.Eip712Validator;

public class Eip712AttestationRequest extends Eip712Validator implements JsonEncodable, Verifiable, Validateable {
  public static final int PLACEHOLDER_CHAIN_ID = 0;
  public static final int DEFAULT_TIME_LIMIT_MS = 100000;

  private final AttestationRequest attestationRequest;
  private final AttestationRequestData data;
  private final String jsonEncoding;
  private final long acceptableTimeLimit;

  public Eip712AttestationRequest(String attestorDomain, String identifier, AttestationType type,
      FullProofOfExponent pok, AsymmetricCipherKeyPair keys) {
    this(attestorDomain, DEFAULT_TIME_LIMIT_MS, identifier, type, pok, keys);
  }

  public Eip712AttestationRequest(String attestorDomain, long acceptableTimeLimit, String identifier,
      AttestationType type, FullProofOfExponent pok, AsymmetricCipherKeyPair keys) {
    super(attestorDomain, new Eip712AttestationRequestEncoder());
    try {
      this.acceptableTimeLimit = acceptableTimeLimit;
      this.attestationRequest = new AttestationRequest(type, pok, keys.getPublic());
      this.jsonEncoding = makeToken(identifier, keys);
      String attestationRequestData = retrieveUnderlyingObject(jsonEncoding);
      this.data = mapper.readValue(attestationRequestData, AttestationRequestData.class);
    } catch (Exception e ) {
      throw new IllegalArgumentException("Could not encode object");
    }
    constructorCheck();
  }

  public Eip712AttestationRequest(String attestorDomain, String jsonEncoding) {
    this(attestorDomain, DEFAULT_TIME_LIMIT_MS, jsonEncoding);
  }

  public Eip712AttestationRequest(String attestorDomain, long acceptableTimeLimit, String jsonEncoding) {
    super(attestorDomain, new Eip712AttestationRequestEncoder());
    try {
      this.acceptableTimeLimit = acceptableTimeLimit;
      this.jsonEncoding = jsonEncoding;
      String attestationRequestData = retrieveUnderlyingObject(jsonEncoding);
      this.data = mapper.readValue(attestationRequestData, AttestationRequestData.class);
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

  String makeToken(String identifier, AsymmetricCipherKeyPair keys) {
    Eip712Issuer issuer = new Eip712Issuer(keys, encoder);
    String address = SignatureUtility.addressFromKey(keys.getPublic());
    String encodedAttestationRequest = URLUtility.encodeData(attestationRequest.getDerEncoding());
    AttestationRequestData data = new AttestationRequestData(
        Eip712AttestationRequestEncoder.USAGE_VALUE,
        identifier, address, encodedAttestationRequest, System.currentTimeMillis());
    return issuer.buildSignedTokenFromJsonObject(data, domain, PLACEHOLDER_CHAIN_ID);
  }

  public String getIdentifier() {
    return data.getIdentifier();
  }

  public AsymmetricKeyParameter getPublicKey() {
    return attestationRequest.getPublicKey();
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
    if (!verifySignature(jsonEncoding, data.getAddress())) {
      return false;
    }
    return true;
  }

  @Override
  public boolean checkValidity() {
    try {
      boolean accept = true;
      accept &= data.getDescription().equals(Eip712AttestationRequestEncoder.USAGE_VALUE);
      accept &= verifyTimeStamp(data.getTimeStamp());
      accept &= data.getAddress().toUpperCase().equals(
          SignatureUtility.addressFromKey(attestationRequest.getPublicKey()).toUpperCase());
      accept &= Nonce.validateNonce(getPok().getNonce(), getIdentifier(),
          data.getAddress(), domain);
      return accept;
    } catch (Exception e) {
      return false;
    }
  }

  private boolean verifyTimeStamp(long timestamp) {
    long currentTime = System.currentTimeMillis();
    // Verify timestamp is still valid and not too old
    if ((timestamp < currentTime + acceptableTimeLimit) &&
        (timestamp > currentTime - acceptableTimeLimit)) {
      return true;
    }
    return false;
  }

}
