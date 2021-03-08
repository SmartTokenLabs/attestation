package com.alphawallet.attestation.eip712;

import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import org.tokenscript.eip712.Eip712Encoder;
import org.tokenscript.eip712.FullEip712InternalData;

public class Eip712AttestationUsageEncoder implements Eip712Encoder {
  static final String PROTOCOL_VERSION = "0.1";

  static final String PRIMARY_NAME = "AttestationUsage";
  static final String DESCRIPTION_NAME = "description";
  static final String PAYLOAD_NAME = "payload";
  static final String IDENTITY_NAME = "identity";
  static final String TIMESTAMP_NAME = "timestamp";//"Timestamp (milliseconds since epoch)";

  static final String USAGE_VALUE = "Prove that the \"identity\" is the identity hidden in attestation contained in\"payload\".";

  public Eip712AttestationUsageEncoder() {
  }

  @Override
  public HashMap<String, List<Entry>> getTypes() {
    HashMap<String, List<Entry>> types = new HashMap<>();
    List<Entry> content = new ArrayList<>();
    content.add(new Entry(PAYLOAD_NAME, STRING));
    content.add(new Entry(DESCRIPTION_NAME, STRING));
    content.add(new Entry(IDENTITY_NAME, STRING));
    content.add(new Entry(TIMESTAMP_NAME, UINT64));
    types.put(PRIMARY_NAME, content);
    List<Entry> domainContent = new ArrayList<>();
    domainContent.add(new Entry("name", STRING));
    domainContent.add(new Entry("version", STRING));
//    domainContent.add(new Entry("chainId", UINT256));
//    domainContent.add(new Entry("verifyingContract", ADDRESS));
//    domainContent.add(new Entry("salt", BYTES32));
    types.put("EIP712Domain", domainContent);
    return types;
  }

  @Override
  public String getPrimaryName() {
    return PRIMARY_NAME;
  }

  @Override
  public String getProtocolVersion() {
    return PROTOCOL_VERSION;
  }

  @Override
  public String getSalt() {
    return null;
  }

  static class AttestationUsageData extends FullEip712InternalData {
    private String identifier;

    public AttestationUsageData() { super(); }

    public AttestationUsageData(String description, String identifier, String payload, long timeStamp) {
      super(description, payload, timestampFormat.format(new Date(timeStamp)));
      this.identifier = identifier;
    }

    public String getIdentifier() {
      return identifier;
    }

    public void setIdentifier(String identifier) {
      this.identifier = identifier;
    }

  }
}
