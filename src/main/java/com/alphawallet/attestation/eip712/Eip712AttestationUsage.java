package com.alphawallet.attestation.eip712;

import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.SignedIdentityAttestation;
import com.alphawallet.attestation.UseAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.Nonce;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.attestation.core.Verifiable;
import com.alphawallet.attestation.eip712.Eip712AttestationUsageEncoder.AttestationUsageData;
import java.io.IOException;
import java.math.BigInteger;
import java.time.Clock;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import org.tokenscript.eip712.Eip712Issuer;
import org.tokenscript.eip712.Eip712Validator;
import org.tokenscript.eip712.JsonEncodable;

public class Eip712AttestationUsage extends Eip712Validator implements JsonEncodable, Verifiable,
    Validateable {
  public static final int PLACEHOLDER_CHAIN_ID = 0;

  private final UseAttestation useAttestation;
  private final AttestationUsageData data;
  private final String jsonEncoding;
  private final AsymmetricKeyParameter publicKey;

  public Eip712AttestationUsage(String attestorDomain, String identifier, UseAttestation useAttestation, AsymmetricKeyParameter signingKey) {
    this(attestorDomain, DEFAULT_TIME_LIMIT_MS, identifier, useAttestation, signingKey);
  }

  public Eip712AttestationUsage(String attestorDomain, long acceptableTimeLimit,
      String identifier, UseAttestation useAttestation,
      AsymmetricKeyParameter signingKey) {
    super(attestorDomain, acceptableTimeLimit, new Eip712AttestationUsageEncoder());
    try {
      this.useAttestation = useAttestation;
      this.jsonEncoding = makeToken(identifier, useAttestation, signingKey);
      this.publicKey = retrievePublicKey(jsonEncoding, AttestationUsageData.class);
      this.data = retrieveUnderlyingObject(jsonEncoding, AttestationUsageData.class);
    } catch (Exception e ) {
      throw new IllegalArgumentException("Could not encode object");
    }
    constructorCheck();
  }

  public Eip712AttestationUsage(String attestorDomain, AsymmetricKeyParameter attestationIssuerVerificationKey, String jsonEncoding) {
    this(attestorDomain, attestationIssuerVerificationKey, DEFAULT_TIME_LIMIT_MS, jsonEncoding);
  }

  public Eip712AttestationUsage(String attestorDomain, AsymmetricKeyParameter attestationIssuerVerificationKey, long acceptableTimeLimit, String jsonEncoding) {
    super(attestorDomain, acceptableTimeLimit, new Eip712AttestationUsageEncoder());
    try {
      this.jsonEncoding = jsonEncoding;
      this.publicKey = retrievePublicKey(jsonEncoding, AttestationUsageData.class);
      this.data = retrieveUnderlyingObject(jsonEncoding, AttestationUsageData.class);
      this.useAttestation = new UseAttestation(URLUtility.decodeData(data.getPayload()), attestationIssuerVerificationKey);
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

  String makeToken(String identifier, UseAttestation useAttestation,
      AsymmetricKeyParameter signingKey) throws IOException {
    Eip712Issuer issuer = new Eip712Issuer(signingKey, encoder);
    String encodedUseAttestation = URLUtility.encodeData(useAttestation.getDerEncoding());
    AttestationUsageData data = new AttestationUsageData(
        Eip712AttestationUsageEncoder.USAGE_VALUE,
        identifier, encodedUseAttestation, Clock.systemUTC().millis());
    return issuer.buildSignedTokenFromJsonObject(data, domain, PLACEHOLDER_CHAIN_ID);
  }

  private boolean proofLinking() {
    BigInteger candidateExponent = AttestationCrypto.mapToCurveMultiplier(getType(), getIdentifier());
    ECPoint commitmentPoint = AttestationCrypto.decodePoint(getAttestation().getUnsignedAttestation().getCommitment());
    ECPoint candidateRiddle = commitmentPoint.subtract(AttestationCrypto.G.multiply(candidateExponent));
    if (!candidateRiddle.equals(getPok().getRiddle())) {
      return false;
    }
    return true;
  }

  public String getIdentifier() {
    return data.getIdentifier();
  }

  public AsymmetricKeyParameter getPublicKey() {
    return publicKey;
  }

  public FullProofOfExponent getPok() {
    return useAttestation.getPok();
  }

  public AttestationType getType() {
    return useAttestation.getType();
  }

  public SignedIdentityAttestation getAttestation() {
    return useAttestation.getAttestation();
  }

  @Override
  public String getJsonEncoding() {
    return jsonEncoding;
  }

  @Override
  public boolean checkValidity() {
    boolean accept = true;
    accept &= useAttestation.checkValidity();
    accept &= data.getDescription().equals(Eip712AttestationUsageEncoder.USAGE_VALUE);
    accept &= verifyTimeStamp(data.getTimestamp());
    accept &= SignatureUtility.verifyKeyAgainstAddress(publicKey, useAttestation.getAttestation().getUnsignedAttestation().getAddress());
    accept &= Nonce.validateNonce(useAttestation.getPok().getNonce(), data.getIdentifier(),
        (useAttestation.getAttestation().getUnsignedAttestation()).getAddress(), domain);
    accept &= proofLinking();
    return accept;
  }

  @Override
  public boolean verify() {
    if (!useAttestation.verify()) {
      return false;
    }
    // Remove the "CN=" prefix of subject to get the address
    String address = useAttestation.getAttestation().getUnsignedAttestation().getAddress();
    if (!verifySignature(jsonEncoding, address, AttestationUsageData.class)) {
      return false;
    }
    return true;
  }
}
