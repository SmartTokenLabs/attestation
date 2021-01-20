package org.tokenscript.auth;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.Attestable;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Authenticator<T extends Attestable> extends JWTCommon {
  private final AsymmetricKeyParameter attestorPublicKey;
  private final String issuerDomain;
  private final KeyPair keys;
  private final AttestableObjectDecoder<T> decoder;
  private final ObjectMapper jsonMapper = new ObjectMapper();

  public Authenticator(AttestableObjectDecoder<T> decoder, PublicKey attestorPublicKey, String issuerDomain, KeyPair signingKeys ) throws Exception {
    if (!verifyDomain(issuerDomain)) {
      throw new RuntimeException("Issuer domain is not a valid domain");
    }
    this.issuerDomain = issuerDomain;
    this.attestorPublicKey = SignatureUtility.restoreKeyFromSPKI(attestorPublicKey.getEncoded());
    this.decoder = decoder;
    Security.addProvider(new BouncyCastleProvider());
    this.keys = signingKeys;
  }


  public byte[] validateRequest(byte[] jsonInput) {
    try {
      UseAttestableRequest request = parseJsonInput(jsonInput);
      validateRequest(request);
      return successResponse(request);
    } catch (Exception e) {
      return failureResponse();
    }
  }

  private UseAttestableRequest parseJsonInput(byte[] jsonInput) {
    try {
      return jsonMapper.readValue(jsonInput, UseAttestableRequest.class);
    } catch (IOException e) {
      throw new IllegalArgumentException("Could not parse input request");
    }
  }

  private void validateRequest(UseAttestableRequest request) throws IllegalArgumentException {
    boolean accept = true;
    // Validate useAttestableObject
    AttestedObject<T> useObject = new AttestedObject<T>(request.getUseAttestableRequest(), decoder, attestorPublicKey);
    accept &= useObject.verify();
    accept &= useObject.checkValidity();
    accept &= verifyTimeStamp(request.getTimeStamp());
    accept &= SignatureUtility.verify(request.getSignable(), request.getSignature(), useObject.getUserPublicKey());
    accept &= verifyDomain(request.getDomain());
    if (!accept) {
      throw new RuntimeException("Could not validate request");
    }
  }

  private boolean verifyDomain(String domain) {
    try {
      // Check if we get a malformed exception
      new URL(domain);
    } catch (MalformedURLException e) {
      return false;
    }
    return true;
  }

  private boolean verifyTimeStamp(long timestamp) {
    long currentTime = System.currentTimeMillis();
    // Verify timestamp is still valid and not too old
    if ((timestamp < currentTime + TIMELIMIT_IN_MS) &&
        (timestamp > System.currentTimeMillis() - TIMELIMIT_IN_MS)) {
      return true;
    }
    return false;
  }

  private byte[] successResponse(UseAttestableRequest request) {
    AttestedObject<T> useObject = new AttestedObject<T>(request.getUseAttestableRequest(), decoder, attestorPublicKey);
    long currentTime = System.currentTimeMillis();
    Builder builder = JWT.create();
    builder.withIssuer("org.alphawallet.auth");
    builder.withSubject(useObject.getAtt().getUnsignedAttestation().getSubject());
    builder.withAudience(request.getDomain());
    builder.withNotBefore(new Date(currentTime));
    builder.withIssuedAt(new Date(currentTime));
    builder.withExpiresAt(new Date(currentTime + TIMELIMIT_IN_MS));
    builder.withJWTId(getJWTID(request, currentTime));
    Security.addProvider(new BouncyCastleProvider());
    return builder.sign(getAlgorithm(keys.getPublic(), keys.getPrivate())).getBytes(StandardCharsets.UTF_8);
  }


  private String getJWTID(UseAttestableRequest request, long now) {
    ByteBuffer toHash = ByteBuffer.allocate((Long.SIZE / 8) + request.getSignable().length);
    toHash.putLong(now);
    toHash.put(request.getSignable());
    byte[] digest = AttestationCrypto.hashWithKeccak(toHash.array());
    return Base64.getEncoder().encodeToString(digest);
  }

  private byte[] failureResponse() {
    return "fail".getBytes(StandardCharsets.UTF_8);
  }

}
