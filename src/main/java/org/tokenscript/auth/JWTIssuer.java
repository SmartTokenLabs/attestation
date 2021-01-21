package org.tokenscript.auth;

import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.Attestable;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class JWTIssuer<T extends Attestable>  extends JWTCommon {
  private final AsymmetricKeyParameter signingKey;

  public JWTIssuer(AsymmetricKeyParameter signingKey) {
    this.signingKey = signingKey;
  }

  public String makeToken(AttestedObject attestedObject, String domain) {
    if (!isValidDomain(domain)) {
      throw new IllegalArgumentException("Invalid domain");
    }
    long currentTime = System.currentTimeMillis();
    Builder builder = JWT.create();
    // Only withAudience, withIssuedAt and withClaim(attestedObjectClaimName) are required
    String encodedObject = URLUtility.encodeData(attestedObject.getDerEncoding());
    builder.withClaim(attestedObjectClaimName, encodedObject);
    builder.withAudience(domain);
    builder.withIssuedAt(new Date(currentTime));
    // withNotBefore, withExpiresAt and withJWTId are OPTIONAL
    builder.withNotBefore(new Date(currentTime));
    builder.withExpiresAt(new Date(currentTime + TIMELIMIT_IN_MS));
    builder.withJWTId(getJWTID(attestedObject, currentTime));
    // Create an unsigned JWT since we need to sign it in a Ethereum compatible way
    String unsignedTokenString = builder.sign(Algorithm.none());
    return web3SignUnsignedJWT(unsignedTokenString);
  }

  private String web3SignUnsignedJWT(String unsignedJwtString) {
    DecodedJWT unsignedTokenJwt = JWT.decode(unsignedJwtString);
    String base64Payload = unsignedTokenJwt.getPayload();
    // According to the JWS standard it must be base64url encoded and contain the encoded protected header concatenated with "."
    String toSign = header + "." + base64Payload;
    byte[] sig = SignatureUtility.signWithWeb3(toSign.getBytes(StandardCharsets.UTF_8), signingKey);
    String base64Sig = URLUtility.encodeData(sig);
    return String.format("%s.%s.%s", header, base64Payload, base64Sig);
  }

  private String getJWTID(AttestedObject request, long now) {
    ByteBuffer toHash = ByteBuffer.allocate((Long.SIZE / 8) + request.getDerEncoding().length);
    toHash.putLong(now);
    toHash.put(request.getDerEncoding());
    byte[] digest = AttestationCrypto.hashWithKeccak(toHash.array());
    return Base64.getEncoder().encodeToString(digest);
  }

}
