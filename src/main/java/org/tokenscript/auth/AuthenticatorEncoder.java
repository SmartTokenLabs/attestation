package org.tokenscript.auth;

import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import org.tokenscript.eip712.Eip712Encoder;

public class AuthenticatorEncoder extends Eip712Encoder {
  private static final String PROTOCOL_VERSION = "0.1";
  private static final String PRIMARY_NAME = "Authentication";//"Signed request to be used only for";
  private static final String USAGE_VALUE = "Single-use authentication";

  public AuthenticatorEncoder(long chainId, SecureRandom random) {
    super(USAGE_VALUE, PROTOCOL_VERSION, PRIMARY_NAME, chainId, random.generateSeed(32));
  }

  @Override
  public HashMap<String, List<Entry>> getTypes() {
    return getDefaultTypes();
  }

}
