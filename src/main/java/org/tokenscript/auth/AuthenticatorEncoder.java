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

  private final SecureRandom random;
  private String salt = null;

  public AuthenticatorEncoder(SecureRandom random) {
    this.random = random;
  }

  @Override
  public HashMap<String, List<Entry>> getTypes() {
    HashMap<String, List<Entry>> types = getDefaultTypes(PRIMARY_NAME);
    types.get(EIP712DOMAIN).add(SALT_DOMAIN_ENTRY);
    return types;
  }

  @Override
  public String getSalt() {
    if (salt == null) {
      salt = Hex.toHexString(random.generateSeed(32));
    }
    return salt;
  }

  @Override
  public String getPrimaryName() {
    return PRIMARY_NAME;
  }

  @Override
  public String getProtocolVersion() {
    return PROTOCOL_VERSION;
  }

}
