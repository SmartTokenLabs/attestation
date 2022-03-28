package org.tokenscript.attestation.eip712;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.InvalidObjectException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.Timestamp;
import org.tokenscript.attestation.core.ASNEncodable;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.URLUtility;
import org.tokenscript.eip712.Eip712Encoder;
import org.tokenscript.eip712.Eip712Signer;
import org.tokenscript.eip712.FullEip712InternalData;

/**
 * Class for issuing EIP712 tokens containing any ASNEncodable object.
 */
public class Eip712ObjectSigner<ObjectT extends ASNEncodable> extends
    Eip712Signer<FullEip712InternalData> {
  private static final Logger logger = LogManager.getLogger(Eip712ObjectSigner.class);
  private final Eip712Encoder encoder;

  public Eip712ObjectSigner(AsymmetricKeyParameter signingKey, Eip712Encoder encoder) {
    super(signingKey, encoder);
    this.encoder = encoder;
  }
  

  public String buildSignedToken(ObjectT attestedObject, String webDomain) {
    try {
      String encodedObject = URLUtility.encodeData(attestedObject.getDerEncoding());
      Timestamp time = new Timestamp();
      FullEip712InternalData auth = new FullEip712InternalData(encoder.getUsageValue(), encodedObject, time);
      return buildSignedTokenFromJsonObject(auth, webDomain);
    } catch (InvalidObjectException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not retrieve DER encoding of attested object", e);
    } catch (JsonProcessingException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not build json token", e);
    }
  }
}
