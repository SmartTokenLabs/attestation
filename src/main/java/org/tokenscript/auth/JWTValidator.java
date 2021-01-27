package org.tokenscript.auth;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.Attestable;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Class for validating JWT tokens containing a useDevconTicket object.
 * The tokens are supposed to be issued by the user for consumption by a third party website.
 *
 * Thus we are abusing the "normal" three-party setting of JWTs since in our case both the
 * issuer and the subject is the same.
 * We furthermore also misuse the formal format of JWTs since we sign using an Ethereum key, and
 * hence the signature with have "Ethereum Signed Message:" as prefix and use Keccak for hashing.
 */
public class JWTValidator<T extends Attestable> extends JWTCommon {
  private final AsymmetricKeyParameter attestorPublicKey;
  private final String domain;
  private final AttestableObjectDecoder<T> decoder;

  public JWTValidator(AttestableObjectDecoder<T> decoder, AsymmetricKeyParameter attestorPublicKey, String domain) throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    if (!isValidDomain(domain)) {
      throw new RuntimeException("Issuer domain is not a valid domain");
    }
    this.domain = domain;
    this.attestorPublicKey = attestorPublicKey;
    this.decoder = decoder;
  }


  public boolean validateRequest(String jsonInput) {
    try {
      DecodedJWT jwt = JWT.decode(jsonInput);
      AttestedObject attestedObject = retrieveAttestedObject(jwt);

      boolean accept = true;
      accept &= validateJWTContent(jwt);
      accept &= verifySignature(jwt, attestedObject.getUserPublicKey());
      accept &= validateAttestedObject(attestedObject);
      return accept;
    } catch (Exception e) {
      return false;
    }
  }

  private AttestedObject retrieveAttestedObject(DecodedJWT jwt) throws IOException {
    String attestedObjectClaim = jwt.getClaim(attestedObjectClaimName).asString();
    byte[] attestedObjectBytes = URLUtility.decodeData(attestedObjectClaim);
    AttestedObject<T> decodedAttestedObject = new AttestedObject<>(attestedObjectBytes, decoder, attestorPublicKey);
    return decodedAttestedObject;
  }

  private boolean validateJWTContent(DecodedJWT jwt) {
    boolean accept = true;
    accept &= header.equals(jwt.getHeader());
    accept &= jwt.getAudience().contains(domain);
    accept &= verifyTimeStamp(jwt.getIssuedAt().getTime());
    return accept;
  }

  private boolean verifySignature(DecodedJWT jwt, AsymmetricKeyParameter pk) {
    try {
      String base64Payload = jwt.getPayload();
      // According to the JWS standard it must be base64url encoded and contain the encoded protected header concatenated with "."
      String message = header + "." + base64Payload;
      byte[] decodedSignature = URLUtility.decodeData(jwt.getSignature());
      return SignatureUtility.verifyEthereumSignature(message.getBytes(StandardCharsets.UTF_8), decodedSignature, pk);
    } catch (Exception e) {
      return false;
    }
  }

  private boolean validateAttestedObject(AttestedObject<T> attestedObject) {
    boolean accept = true;
    // Validate useAttestableObject
    accept &= attestedObject.verify();
    accept &= attestedObject.checkValidity();
    return accept;
  }

  private boolean verifyTimeStamp(long timestamp) {
    long currentTime = System.currentTimeMillis();
    // Verify timestamp is still valid and not too old
    if ((timestamp < currentTime + TIMELIMIT_IN_MS) &&
        (timestamp > currentTime - TIMELIMIT_IN_MS)) {
      return true;
    }
    return false;
  }

}
