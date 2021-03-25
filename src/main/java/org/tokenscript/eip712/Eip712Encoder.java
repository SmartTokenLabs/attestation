package org.tokenscript.eip712;

import com.alphawallet.attestation.ValidationTools;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import org.bouncycastle.util.encoders.Hex;

public abstract class Eip712Encoder {
  protected static final String STRING = "string";
  protected static final String BYTES32 = "bytes32";
  protected static final String UINT64 = "uint64";
  protected static final String UINT256 = "uint256";
  protected static final String ADDRESS = "address";

  protected static final String EIP712DOMAIN = "EIP712Domain";

  protected static final String TIMESTAMP_NAME = "timestamp";
  protected static final String DESCRIPTION_NAME = "description";
  protected static final String PAYLOAD_NAME = "payload";

  private final Long chainId;
  private final String salt;
  private final String protocolVersion;
  private final String primaryName;
  private final String verifyingContract;
  private final String usageValue;

  public Eip712Encoder(String usageValue, String protocolVersion, String primaryName,
      Long chainId, String verifyingContract, byte[] salt) {
    this.usageValue = usageValue;
    this.protocolVersion = protocolVersion;
    this.primaryName = primaryName;
    this.chainId = chainId;
    this.salt = parseSalt(salt);
    if (!ValidationTools.isNullOrAddress(verifyingContract)) {
      throw new RuntimeException("Not a valid address given as verifying contract");
    }
    this.verifyingContract = verifyingContract;
  }

  private String parseSalt(byte[] salt) {
    if (salt != null) {
      if (salt.length == 32) {
        return  "0x" + Hex.toHexString(salt);
      } else {
        throw new RuntimeException("Salt must be 32 bytes");
      }
    }
    return null;
  }

  public Eip712Encoder(String usageValue, String protocolVersion, String primaryName,
      Long chainId, byte[] salt) {
    this(usageValue, protocolVersion, primaryName, chainId, null, salt);
  }

  public Eip712Encoder(String usageValue, String protocolVersion, String primaryName,
      Long chainId) {
    this(usageValue, protocolVersion, primaryName, chainId, null);
  }

  public Eip712Encoder(String usageValue, String protocolVersion, String primaryName) {
    this(usageValue, protocolVersion, primaryName, null, null);
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
    domainContent.add(new Entry("version", STRING));
    if (chainId != null) {
      domainContent.add(new Entry("chainId", UINT256));
    }
    if (verifyingContract != null) {
      domainContent.add(new Entry("verifyingContract", ADDRESS));
    }
    if (salt != null) {
      domainContent.add(new Entry("salt", BYTES32));
    }
    types.put(EIP712DOMAIN, domainContent);
    return types;
  }
  public abstract HashMap<String, List<Entry>> getTypes();

  public String getUsageValue() { return usageValue; }

  public String getPrimaryName() {
    return primaryName;
  }

  public String getProtocolVersion() {
    return protocolVersion;
  }

  public String getSalt() {
    return salt;
  }

  public Long getChainId() {
    return chainId;
  }

  public String getVerifyingContract() {
    return verifyingContract;
  }

  // Timestamp with millisecond accuracy and timezone info
  public static final SimpleDateFormat TIMESTAMP_FORMAT = new SimpleDateFormat("EEE MMM d yyyy HH:mm:ss 'GMT'Z", Locale.US);

  public static long stringTimestampToLong(String timestamp) {
    try {
      return TIMESTAMP_FORMAT.parse(timestamp).getTime();
    } catch (ParseException e) {
      throw new RuntimeException(e);
    }
  }
}
