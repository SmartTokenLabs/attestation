package org.tokenscript.eip712;

import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;

public interface Eip712Encoder {

  String STRING = "string";
  String BYTES32 = "bytes32";
  String UINT64 = "uint64";
  String UINT256 = "uint256";
  String ADDRESS = "address";

  String TIMESTAMP_NAME = "timestamp";
  String DESCRIPTION_NAME = "description";
  String PAYLOAD_NAME = "payload";
  String IDENTIFIER_NAME = "identifier";

  public HashMap<String, List<Entry>> getTypes();
  public String getPrimaryName();
  public String getProtocolVersion();
  public String getSalt();

  // Timestamp with millisecond accuracy and timezone info
  public static final SimpleDateFormat timestampFormat = new SimpleDateFormat("yyyy.MM.dd 'at' HH:mm:ss.SSS z");
}
