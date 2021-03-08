package org.tokenscript.auth;

import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.eip712.Eip712Encoder;

public class AuthenticatorEncoder implements Eip712Encoder {
  static final String PROTOCOL_VERSION = "0.1";

  static final String PRIMARY_NAME = "Authentication";//"Signed request to be used only for";
  static final String DESCRIPTION_NAME = "description";//"Signed request to be used only for";
  static final String PAYLOAD_NAME = "payload";//"Cryptographic proof of identity";
  static final String TIMESTAMP_NAME = "timestamp";//"Timestamp (milliseconds since epoch)";

  static final String USAGE_VALUE = "Single-use authentication";

  private final SecureRandom random;
  private String salt = null;

  public AuthenticatorEncoder(SecureRandom random) {
    this.random = random;
  }

  @Override
  public HashMap<String, List<Entry>> getTypes() {
    HashMap<String, List<Entry>> types = new HashMap<>();
    List<Entry> content = new ArrayList<>();
    content.add(new Entry(PAYLOAD_NAME, STRING));
    content.add(new Entry(DESCRIPTION_NAME, STRING));
    content.add(new Entry(TIMESTAMP_NAME, UINT64));
    types.put(PRIMARY_NAME, content);
    List<Entry> domainContent = new ArrayList<>();
    domainContent.add(new Entry("name", STRING));
    domainContent.add(new Entry("version", STRING));
//    domainContent.add(new Entry("chainId", UINT256));
//    domainContent.add(new Entry("verifyingContract", ADDRESS));
    domainContent.add(new Entry("salt", BYTES32));
    types.put("EIP712Domain", domainContent);
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
