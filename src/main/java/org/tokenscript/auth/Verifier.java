package org.tokenscript.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

public class Verifier extends JWTCommon {
  private final PublicKey verificationKey;
  private final JWTVerifier verifier;

  public Verifier(String audience, PublicKey verificationKey) {
    // todo add cert verification
    this.verificationKey = verificationKey;
    this.verifier = JWT.require(getAlgorithm(this.verificationKey, null))
        .withIssuer("org.alphawallet.auth")
        .acceptLeeway(TIMELIMIT_IN_MS)
        .acceptExpiresAt(TIMELIMIT_IN_MS)
        .withAudience(audience)
        .build(); //Reusable verifier instance
  }

  public boolean verifyToken(byte[] jwt) {
    try {
      verifier.verify(new String(jwt, StandardCharsets.UTF_8));
      return true;
    } catch (JWTVerificationException exception){
      return false;
    }
  }
}
