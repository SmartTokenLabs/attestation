package org.tokenscript.eip712;

import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public abstract class Eip712Encoder {

  public static final String STRING = "string";
  public static final String BYTES32 = "bytes32";
  public static final String UINT64 = "uint64";
  public static final String UINT256 = "uint256";
  public static final String ADDRESS = "address";

  public static final String EIP712DOMAIN = "EIP712Domain";
  public static final Entry SALT_DOMAIN_ENTRY = new Entry("salt", BYTES32);

  public static final String TIMESTAMP_NAME = "timestamp";
  public static final String DESCRIPTION_NAME = "description";
  public static final String PAYLOAD_NAME = "payload";

  // Other relevant tags
  public static final Entry ADDRESS_ENTRY = new Entry("address", STRING);
  public static final Entry IDENTIFIER_ENTRY = new Entry("identifier", STRING);

  public HashMap<String, List<Entry>> getDefaultTypes(String primaryName) {
    HashMap<String, List<Entry>> types = new HashMap<>();
    List<Entry> content = new ArrayList<>();
    content.add(new Entry(PAYLOAD_NAME, STRING));
    content.add(new Entry(DESCRIPTION_NAME, STRING));
    content.add(new Entry(TIMESTAMP_NAME, STRING));
    types.put(primaryName, content);
    List<Entry> domainContent = new ArrayList<>();
    domainContent.add(new Entry("name", STRING));
    domainContent.add(new Entry("version", STRING));
//  domainContent.add(new Entry("chainId", UINT256));
//  domainContent.add(new Entry("verifyingContract", ADDRESS));
    types.put("EIP712Domain", domainContent);
    return types;
  }
  public abstract HashMap<String, List<Entry>> getTypes();
  public abstract String getPrimaryName();
  public abstract String getProtocolVersion();
  public abstract String getSalt();

  // Timestamp with millisecond accuracy and timezone info
  public static final SimpleDateFormat timestampFormat = new SimpleDateFormat("yyyy.MM.dd 'at' HH:mm:ss.SSS z");
}
