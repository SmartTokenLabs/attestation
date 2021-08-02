package org.tokenscript.auth;

import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.eip712.Timestamp;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.security.SecureRandom;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.eip712.Eip712Issuer;
import org.tokenscript.eip712.FullEip712InternalData;

/**
 * Class for issuing EIP712 tokens containing a useDevconTicket object.
 * The tokens are supposed to be issued by the user for consumption by a third party website.
 */
public class Eip712AuthIssuer extends Eip712Issuer<FullEip712InternalData> {
  private final AuthenticatorEncoder encoder;

  public Eip712AuthIssuer(AsymmetricKeyParameter signingKey, long chainId) {
    this(signingKey, new AuthenticatorEncoder(chainId, new SecureRandom()));
  }

  public Eip712AuthIssuer(AsymmetricKeyParameter signingKey, AuthenticatorEncoder encoder) {
    super(signingKey, encoder);
    this.encoder = encoder;
  }
  

  public String buildSignedToken(AttestedObject attestedObject, String webDomain) throws JsonProcessingException {
    String encodedObject = URLUtility.encodeData(attestedObject.getDerEncoding());
    Timestamp time = new Timestamp();
    FullEip712InternalData auth = new FullEip712InternalData(encoder.getUsageValue(), encodedObject, time);
    return buildSignedTokenFromJsonObject(auth, webDomain);
  }
}
