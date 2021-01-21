package org.tokenscript.auth;

import com.alphawallet.attestation.core.URLUtility;
import com.auth0.jwt.algorithms.Algorithm;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Class for JWS JSON serialization based on JWT but with Ethereum compatible signing
 */
public abstract class JWTCommon {
  public static final String attestedObjectClaimName = "org.tokenscript.auth.attestedObject";
  // Not exactly following JWT since that requires a standard signature using SHA256
  // The header ES256 implies that secp256r1 has been used with SHA 256 to sign which
  // which is the closets we get to the standard
  // To instead avoid issued we define our own header algorithm WEB3
  public static final String header = URLUtility.encodeData(
      "{\"typ\":\"JWT\",\n\"alg\":\"WEB3\"}".getBytes(StandardCharsets.UTF_8));
  public static final long TIMELIMIT_IN_MS = 10000;

  protected boolean isValidDomain(String domain) {
    try {
      // Check if we get a malformed exception
      new URL(domain);
    } catch (MalformedURLException e) {
      return false;
    }
    return true;
  }

  protected Algorithm getAlgorithm(PublicKey pk, PrivateKey secretKey) {
    // SHA 512 is always used for hashing since Auth0 will never accept a key with domain less than the digest size
    // This means that if we are unlucky it won't even accept a 512 bit ECDSA key here if the bit representation happen to be too small
    if (pk instanceof ECPublicKey) {
      return Algorithm.ECDSA512((ECPublicKey) pk, (ECPrivateKey) secretKey);
    } else if (pk instanceof RSAPublicKey) {
      return Algorithm.RSA512((RSAPublicKey) pk, (RSAPrivateKey) secretKey);
    } else {
      throw new UnsupportedOperationException("The key used to sign with is not EC or RSA which are currently the only supported types.");
    }
  }

}
