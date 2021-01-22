package org.tokenscript.auth;

import com.alphawallet.attestation.core.URLUtility;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

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

}
