package org.tokenscript.auth;

import com.alphawallet.token.web.Ethereum.web3j.StructuredData;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Domain;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.EIP712Message;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.auth.model.InternalAuthenticationData;

public class Eip712Authenticator {
  static final String PROTOCOL_VERSION = "0.1";

  static final String STRING = "string";
  static final String BYTES32 = "bytes32";
  static final String UINT64 = "uint64";
  static final String UINT256 = "uint256";
  static final String ADDRESS = "address";

  static final String PRIMARY_NAME = "Authentication";//"Signed request to be used only for";
  static final String DESCRIPTION_NAME = "description";//"Signed request to be used only for";
  static final String PAYLOAD_NAME = "payload";//"Cryptographic proof of identity";
  static final String TIMESTAMP_NAME = "timestamp";//"Timestamp (milliseconds since epoch)";

  static final String USAGE_VALUE = "Single-use authentication";

  protected final ObjectMapper mapper = new ObjectMapper();
  private final SecureRandom random;

  public Eip712Authenticator(SecureRandom random) {
    this.random = random;
  }

  public static HashMap<String, List<Entry>> getTypes() {
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

  public String jsonEncode(String payload, String webDomain) {
    try {
      InternalAuthenticationData auth = new InternalAuthenticationData(USAGE_VALUE, payload, System.currentTimeMillis());
      String salt = Hex.toHexString(random.generateSeed(32));
      StructuredData.EIP712Domain domain = new EIP712Domain(webDomain, PROTOCOL_VERSION, null, null, salt);
      StructuredData.EIP712Message message = new EIP712Message(getTypes(), PRIMARY_NAME, auth, domain);
      return mapper.writeValueAsString(message);
    } catch ( IOException e) {
      throw new InternalError("The internal json to object mapping failed");
    }
  }
}
