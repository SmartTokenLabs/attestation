package org.tokenscript.auth;

import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.URLUtility;
import org.tokenscript.eip712.FullEip712InternalData;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.tokenscript.eip712.Eip712Issuer;

/**
 * Class for issuing EIP712 tokens containing a useDevconTicket object.
 * The tokens are supposed to be issued by the user for consumption by a third party website.
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
    FullEip712InternalData auth = new FullEip712InternalData(authenticator.USAGE_VALUE, encodedObject, System.currentTimeMillis());
    return buildSignedTokenFromJsonObject(auth, webDomain, chainId);
  }
}
