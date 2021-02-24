package org.tokenscript.auth;

import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.URLUtility;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.tokenscript.auth.AuthenticatorEncoder.InternalAuthenticationData;
import org.tokenscript.eip712.Eip712Issuer;

/**
 * Class for issuing JWT tokens containing a useDevconTicket object.
 * The tokens are supposed to be issued by the user for consumption by a third party website.
 *
 * Thus we are abusing the "normal" three-party setting of JWTs since in our case both the
 * issuer and the subject is the same.
 * We furthermore also misuse the formal format of JWTs since we sign using an Ethereum key, and
 * hence the signature with have "Ethereum Signed Message:" as prefix and use Keccak for hashing.
 */
public class Eip712AuthIssuer extends Eip712Issuer {
  private final AuthenticatorEncoder authenticator;

  public Eip712AuthIssuer(AsymmetricCipherKeyPair signingKeys) {
    this(signingKeys, new AuthenticatorEncoder(new SecureRandom()));
  }

  public Eip712AuthIssuer(AsymmetricCipherKeyPair signingKeys, AuthenticatorEncoder authenticator) {
    super(signingKeys, authenticator);
    this.authenticator = authenticator;
  }

  public String buildSignedToken(AttestedObject attestedObject, String webDomain) {
    return buildSignedToken(attestedObject, webDomain, 0);
  }

  public String buildSignedToken(AttestedObject attestedObject, String webDomain, int chainId) {
    String encodedObject = URLUtility.encodeData(attestedObject.getDerEncoding());
    InternalAuthenticationData auth = new InternalAuthenticationData(authenticator.USAGE_VALUE, encodedObject, System.currentTimeMillis());
    return buildSignedTokenFromJsonObject(auth, webDomain, chainId);
  }
}
