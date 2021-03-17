package org.tokenscript.auth;

import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.eip712.Eip712Encoder;

public class AuthenticatorEncoder extends Eip712Encoder {
  static final String PROTOCOL_VERSION = "0.1";

  static final String PRIMARY_NAME = "Authentication";//"Signed request to be used only for";
  static final String USAGE_VALUE = "Single-use authentication";

  public AuthenticatorEncoder(long chainId, SecureRandom random) {
    super(PROTOCOL_VERSION, PRIMARY_NAME, chainId, Hex.toHexString(random.generateSeed(32)));
  }

  @Override
  public HashMap<String, List<Entry>> getTypes() {
    return getDefaultTypes();
  }
}
