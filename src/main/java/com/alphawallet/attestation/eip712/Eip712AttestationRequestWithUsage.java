package com.alphawallet.attestation.eip712;

import com.alphawallet.attestation.AttestationRequestWithUsage;
import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.Nonce;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.attestation.core.Verifiable;
import com.alphawallet.attestation.eip712.Eip712AttestationRequestWithUsageEncoder.AttestationRequestWUsageData;
import com.alphawallet.attestation.eip712.Eip712AttestationUsageEncoder.AttestationUsageData;
import java.io.IOException;
import java.time.Clock;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.eip712.Eip712Encoder;
import org.tokenscript.eip712.Eip712Issuer;
import org.tokenscript.eip712.Eip712Validator;
import org.tokenscript.eip712.JsonEncodable;

public class Eip712AttestationRequestWithUsage extends Eip712Validator implements JsonEncodable,
    Verifiable, Validateable {
  public static final long DEFAULT_TOKEN_TIME_LIMIT = 1000 * 60 * 60 * 24 * 7; // 1 week

  private final long maxTokenValidityInMs;
  private final AttestationRequestWithUsage attestationRequestWithUsage;
  private final AttestationRequestWUsageData data;
  private final String jsonEncoding;
  private final AsymmetricKeyParameter userPublicKey;

  public Eip712AttestationRequestWithUsage(String attestorDomain, String identifier, String address,
      AttestationRequestWithUsage attestationRequestWithUsage, AsymmetricKeyParameter signingKey) {
    this(attestorDomain, DEFAULT_TIME_LIMIT_MS, DEFAULT_TOKEN_TIME_LIMIT, identifier, address,
        attestationRequestWithUsage, signingKey);
  }

  public Eip712AttestationRequestWithUsage(String attestorDomain, long acceptableTimeLimit,
      long maxTokenValidityInMs, String identifier, String address, AttestationRequestWithUsage attestationRequestWithUsage,
      AsymmetricKeyParameter signingKey) {
    super(attestorDomain, acceptableTimeLimit, new Eip712AttestationRequestWithUsageEncoder());
    try {
      this.maxTokenValidityInMs = maxTokenValidityInMs;
      this.attestationRequestWithUsage = attestationRequestWithUsage;
      this.jsonEncoding = makeToken(identifier, address, attestationRequestWithUsage, signingKey);
      this.userPublicKey = retrieveUserPublicKey(jsonEncoding, AttestationRequestWUsageData.class);
      this.data = retrieveUnderlyingObject(jsonEncoding, AttestationRequestWUsageData.class);
    } catch (Exception e ) {
      throw new IllegalArgumentException("Could not encode object");
    }
    constructorCheck();
  }

  public Eip712AttestationRequestWithUsage(String attestorDomain, String jsonEncoding) {
    this(attestorDomain, DEFAULT_TIME_LIMIT_MS, DEFAULT_TOKEN_TIME_LIMIT, jsonEncoding);
  }

  public Eip712AttestationRequestWithUsage(String attestorDomain,
      long acceptableTimeLimit, long maxTokenValidityInMs, String jsonEncoding) {
    super(attestorDomain, acceptableTimeLimit, new Eip712AttestationRequestWithUsageEncoder());
    try {
      this.maxTokenValidityInMs = maxTokenValidityInMs;
      this.jsonEncoding = jsonEncoding;
      this.userPublicKey = retrieveUserPublicKey(jsonEncoding, AttestationRequestWUsageData.class);
      this.data = retrieveUnderlyingObject(jsonEncoding, AttestationRequestWUsageData.class);
      this.attestationRequestWithUsage = new AttestationRequestWithUsage(URLUtility.decodeData(data.getPayload()));
    } catch (Exception e ) {
      throw new IllegalArgumentException("Could not decode object");
    }
    constructorCheck();
  }

  void constructorCheck() throws IllegalArgumentException {
    if (!verify()) {
      throw new IllegalArgumentException("Could not verify Eip712 use attestation");
    }
  }

  String makeToken(String identifier, String address, AttestationRequestWithUsage attestationRequestWithUsage,
      AsymmetricKeyParameter signingKey) throws IOException {
    Eip712Issuer issuer = new Eip712Issuer<AttestationUsageData>(signingKey, encoder);
    String encodedUseAttestation = URLUtility.encodeData(attestationRequestWithUsage.getDerEncoding());
    long now = Clock.systemUTC().millis();
    long expirationTime = now + maxTokenValidityInMs;
    AttestationRequestWUsageData data = new AttestationRequestWUsageData(
        encoder.getUsageValue(),
        identifier, encodedUseAttestation, now, expirationTime);
    return issuer.buildSignedTokenFromJsonObject(data, domain);
  }

  public String getIdentifier() {
    return data.getIdentifier();
  }

  public AsymmetricKeyParameter getUserPublicKey() {
    return userPublicKey;
  }

  public FullProofOfExponent getPok() {
    return attestationRequestWithUsage.getPok();
  }

  public AttestationType getType() {
    return attestationRequestWithUsage.getType();
  }

  public AsymmetricKeyParameter getSessionPublicKey() {
    return attestationRequestWithUsage.getSessionPublicKey();
  }

  @Override
  public String getJsonEncoding() {
    return jsonEncoding;
  }

  @Override
  public boolean checkValidity() {
    long nonceMinTime = encoder.stringTimestampToLong(data.getExpirationTime()) - maxTokenValidityInMs;
    long nonceMaxTime = encoder.stringTimestampToLong(data.getExpirationTime());
    if (!Nonce.validateNonce(attestationRequestWithUsage.getPok().getNonce(),
        SignatureUtility.addressFromKey(userPublicKey), domain, nonceMinTime, nonceMaxTime)) {
      return false;
    }
    if (!data.getDescription().equals(encoder.getUsageValue())) {
      return false;
    }
    if (!validateTime(data.getTimestamp(), data.getExpirationTime())) {
      return false;
    }
    return true;
  }

  boolean validateTime(String timestamp, String expirationTime) {
    long timestampMs = Eip712Encoder.stringTimestampToLong(timestamp);
    long expirationTimeMs = Eip712Encoder.stringTimestampToLong(expirationTime);
    long currentTime = Clock.systemUTC().millis();
    // If timestamp is in the future
    if (timestampMs > currentTime + acceptableTimeLimitMs) {
      return false;
    }
    // If token has expired
    if (expirationTimeMs < currentTime - acceptableTimeLimitMs) {
      return false;
    }
    // If the token is valid for too long
    if (expirationTimeMs - timestampMs > maxTokenValidityInMs) {
      return false;
    }
    return true;
  }

  @Override
  public boolean verify() {
    if (!attestationRequestWithUsage.verify()) {
      return false;
    }
    if (!verifySignature(jsonEncoding, SignatureUtility.addressFromKey(userPublicKey), AttestationRequestWUsageData.class)) {
      return false;
    }
    return true;
  }
}
