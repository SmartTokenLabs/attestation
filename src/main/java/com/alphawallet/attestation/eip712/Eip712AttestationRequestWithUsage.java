package com.alphawallet.attestation.eip712;

import static com.alphawallet.attestation.eip712.Timestamp.DEFAULT_TIME_LIMIT_MS;
import static com.alphawallet.attestation.eip712.Timestamp.DEFAULT_TOKEN_TIME_LIMIT;

import com.alphawallet.attestation.AttestationRequestWithUsage;
import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.ExceptionUtil;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.attestation.core.Verifiable;
import com.alphawallet.attestation.eip712.Eip712AttestationRequestWithUsageEncoder.AttestationRequestWUsageData;
import com.alphawallet.attestation.eip712.Eip712AttestationUsageEncoder.AttestationUsageData;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.eip712.Eip712Issuer;
import org.tokenscript.eip712.Eip712Validator;
import org.tokenscript.eip712.JsonEncodable;

public class Eip712AttestationRequestWithUsage extends Eip712Validator implements JsonEncodable,
    Verifiable, Validateable, TokenValidateable {
  private static final Logger logger = LogManager.getLogger(Eip712AttestationRequestWithUsage.class);

  private final long maxTokenValidityInMs;
  private final long acceptableTimeLimit;
  private final AttestationRequestWithUsage attestationRequestWithUsage;
  private final AttestationRequestWUsageData data;
  private final String jsonEncoding;
  private final AsymmetricKeyParameter userPublicKey;

  public Eip712AttestationRequestWithUsage(String attestorDomain, String identifier,
      AttestationRequestWithUsage attestationRequestWithUsage, AsymmetricKeyParameter signingKey) {
    this(attestorDomain, DEFAULT_TIME_LIMIT_MS, DEFAULT_TOKEN_TIME_LIMIT,
        identifier, attestationRequestWithUsage, signingKey);
  }

  public Eip712AttestationRequestWithUsage(String attestorDomain,
      long acceptableTimeLimit, long maxTokenValidityInMs, String identifier,
      AttestationRequestWithUsage attestationRequestWithUsage, AsymmetricKeyParameter signingKey) {
    super(attestorDomain, new Eip712AttestationRequestWithUsageEncoder());
    try {
      this.acceptableTimeLimit = acceptableTimeLimit;
      this.maxTokenValidityInMs = maxTokenValidityInMs;
      this.attestationRequestWithUsage = attestationRequestWithUsage;
      this.jsonEncoding = makeToken(identifier, attestationRequestWithUsage, signingKey);
      this.userPublicKey = retrieveUserPublicKey(jsonEncoding, AttestationRequestWUsageData.class);
      this.data = retrieveUnderlyingObject(jsonEncoding, AttestationRequestWUsageData.class);
    } catch (Exception e ) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not encode object"));
    }
    constructorCheck();
  }

  public Eip712AttestationRequestWithUsage(String attestorDomain, String jsonEncoding) {
    this(attestorDomain, DEFAULT_TIME_LIMIT_MS, DEFAULT_TOKEN_TIME_LIMIT, jsonEncoding);
  }

  public Eip712AttestationRequestWithUsage(String attestorDomain,
      long acceptableTimeLimit, long maxTokenValidityInMs, String jsonEncoding) {
    super(attestorDomain, new Eip712AttestationRequestWithUsageEncoder());
    try {
      this.acceptableTimeLimit = acceptableTimeLimit;
      this.maxTokenValidityInMs = maxTokenValidityInMs;
      this.jsonEncoding = jsonEncoding;
      this.userPublicKey = retrieveUserPublicKey(jsonEncoding, AttestationRequestWUsageData.class);
      this.data = retrieveUnderlyingObject(jsonEncoding, AttestationRequestWUsageData.class);
      this.attestationRequestWithUsage = new AttestationRequestWithUsage(URLUtility.decodeData(data.getPayload()));
    } catch (Exception e ) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not decode object"));
    }
    constructorCheck();
  }

  void constructorCheck() throws IllegalArgumentException {
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not verify Eip712 use attestation"));
    }
  }

  String makeToken(String identifier, AttestationRequestWithUsage attestationRequestWithUsage,
      AsymmetricKeyParameter signingKey) throws IOException {
    Eip712Issuer issuer = new Eip712Issuer<AttestationUsageData>(signingKey, encoder);
    String encodedUseAttestation = URLUtility.encodeData(attestationRequestWithUsage.getDerEncoding());
    Timestamp now = new Timestamp();
    Timestamp expirationTime = new Timestamp(now.getTime() + maxTokenValidityInMs);
    AttestationRequestWUsageData data = new AttestationRequestWUsageData(
        encoder.getUsageValue(), identifier, encodedUseAttestation, now, expirationTime);
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

  /**
   * Verify that an attestation can be issued. I.e. the nonce is not expired
   */
  @Override
  public boolean checkValidity() {
    if (!testNonceAndDescription(acceptableTimeLimit)) {
      logger.error("The object can no longer be used as attestation request. Nonce validation failed");
      return false;
    }
    return true;
  }

  /**
   * Verify that the object can be used as a usage token. I.e. the token timestamp has not expired.
   * Note that the object can still be used as a token after the nonce for issuance has expired.
   */
  @Override
  public boolean checkTokenValidity() {
    Timestamp time = new Timestamp(data.getTimestamp());
    time.setValidity(maxTokenValidityInMs);
    if (!time.validateAgainstExpiration(Timestamp.stringTimestampToLong(data.getExpirationTime()))) {
      logger.error("The object can no longer be used as a request token. It is expired.");
      return false;
    }
    // Nonce validation must still happen since this also verifies user's address and receiver's domain
    if (!testNonceAndDescription(maxTokenValidityInMs)) {
      logger.error("The object can no longer be used as a request token. Nonce validation failed");
      return false;
    }
    return true;
  }

  private boolean testNonceAndDescription(long timeLimit) {
    long nonceMinTime = Timestamp.stringTimestampToLong(data.getTimestamp()) - timeLimit;
    long nonceMaxTime = Timestamp.stringTimestampToLong(data.getTimestamp()) + timeLimit;
    if (!Nonce.validateNonce(attestationRequestWithUsage.getPok().getNonce(),
        SignatureUtility.addressFromKey(userPublicKey), domain, new Timestamp(nonceMinTime), new Timestamp(nonceMaxTime))) {
      logger.error("Nonce validation failed");
      return false;
    }
    if (!data.getDescription().equals(encoder.getUsageValue())) {
      logger.error("Description field is incorrect");
      return false;
    }
    return true;
  }

  @Override
  public boolean verify() {
    if (!attestationRequestWithUsage.verify()) {
      logger.error("Could not verify signature");
      return false;
    }
    return true;
  }
}
