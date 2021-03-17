package org.tokenscript.auth;

import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.URLUtility;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.security.SecureRandom;
import java.time.Clock;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.eip712.Eip712Issuer;
import org.tokenscript.eip712.FullEip712InternalData;

/**
 * Class for issuing EIP712 tokens containing a useDevconTicket object.
 * The tokens are supposed to be issued by the user for consumption by a third party website.
 */
public class Eip712AuthIssuer extends Eip712Issuer<FullEip712InternalData> {
  private final AuthenticatorEncoder authenticator;

  public Eip712AuthIssuer(AsymmetricKeyParameter signingKey, long chainId) {
    this(signingKey, new AuthenticatorEncoder(chainId, new SecureRandom()));
  }

  public Eip712AuthIssuer(AsymmetricKeyParameter signingKey, AuthenticatorEncoder authenticator) {
    super(signingKey, authenticator);
    this.authenticator = authenticator;
  }
  

  public String buildSignedToken(AttestedObject attestedObject, String webDomain) throws JsonProcessingException {
    String encodedObject = URLUtility.encodeData(attestedObject.getDerEncoding());
    FullEip712InternalData auth = new FullEip712InternalData(authenticator.USAGE_VALUE, encodedObject, Clock
        .systemUTC().millis());
    return buildSignedTokenFromJsonObject(auth, webDomain);
  }
}
