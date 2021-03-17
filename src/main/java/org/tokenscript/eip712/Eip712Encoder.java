package org.tokenscript.eip712;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import org.bouncycastle.util.encoders.Hex;

public abstract class Eip712Encoder {

  public static final String STRING = "string";
  public static final String BYTES32 = "bytes32";
  public static final String UINT64 = "uint64";
  public static final String UINT256 = "uint256";
  public static final String ADDRESS = "address";

  public static final String EIP712DOMAIN = "EIP712Domain";

  public static final String TIMESTAMP_NAME = "timestamp";
  public static final String DESCRIPTION_NAME = "description";
  public static final String PAYLOAD_NAME = "payload";

  // Other relevant tags
  public static final Entry ADDRESS_ENTRY = new Entry("address", STRING);
  public static final Entry IDENTIFIER_ENTRY = new Entry("identifier", STRING);

  private final Long chainId;
  private final String salt;
  private final String protocolVersion;
  private final String primaryName;

  public Eip712Encoder(String protocolVersion, String primaryName, Long chainId, String salt) {
    this.protocolVersion = protocolVersion;
    this.primaryName = primaryName;
    this.chainId = chainId;
    this.salt = salt;
  }

  public Eip712Encoder(String protocolVersion, String primaryName, Long chainId) {
    this(protocolVersion, primaryName, chainId, null);
  }

  public static String computePayloadDigest(String payload) {
    return Hex.toHexString(AttestationCrypto.hashWithKeccak(payload.getBytes(
        StandardCharsets.UTF_8)));
  }

  public HashMap<String, List<Entry>> getDefaultTypes() {
    HashMap<String, List<Entry>> types = new HashMap<>();
    List<Entry> content = new ArrayList<>();
    content.add(new Entry(PAYLOAD_NAME, STRING));
    content.add(new Entry(DESCRIPTION_NAME, STRING));
    content.add(new Entry(TIMESTAMP_NAME, STRING));
    types.put(primaryName, content);
    List<Entry> domainContent = new ArrayList<>();
    domainContent.add(new Entry("name", STRING));
    if (protocolVersion != null) {
      domainContent.add(new Entry("version", STRING));
    }
    if (chainId != null) {
      domainContent.add(new Entry("chainId", UINT256));
    }
    if (salt != null) {
      domainContent.add(new Entry("salt", BYTES32));
    }
//  domainContent.add(new Entry("verifyingContract", ADDRESS));
    types.put("EIP712Domain", domainContent);
    return types;
  }
  public abstract HashMap<String, List<Entry>> getTypes();

  public String getPrimaryName() {
    return primaryName;
  }

  public String getProtocolVersion() {
    return protocolVersion;
  }

  public String getSalt() {
    return salt;
  }
  public long getChainId() {
    return chainId;
  }

  // Timestamp with millisecond accuracy and timezone info
  public static final SimpleDateFormat timestampFormat = new SimpleDateFormat("EEE MMM d yyyy HH:mm:ss 'GMT'Z", Locale.US);
}
