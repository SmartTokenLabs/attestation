package com.alphawallet.attestation.eip712;

import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import org.tokenscript.eip712.Eip712Encoder;
import org.tokenscript.eip712.FullEip712InternalData;

public class Eip712AttestationRequestEncoder implements Eip712Encoder {
  static final String PROTOCOL_VERSION = "0.1";

  static final String PRIMARY_NAME = "AttestationRequest";
  static final String ADDRESS_NAME = "address";
  static final String USAGE_VALUE = "Linking Ethereum address to phone or email";

  public Eip712AttestationRequestEncoder() {
  }

  public HashMap<String, List<Entry>> getTypes() {
    HashMap<String, List<Entry>> types = new HashMap<>();
    List<Entry> content = new ArrayList<>();
    content.add(new Entry(PAYLOAD_NAME, STRING));
    content.add(new Entry(DESCRIPTION_NAME, STRING));
    content.add(new Entry(IDENTIFIER_NAME, STRING));
    content.add(new Entry(ADDRESS_NAME, ADDRESS));
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

  static class AttestationRequestInternalData extends FullEip712InternalData {
    private String identifier;
    // TODO This should actually be of type Address, but currently this type of the web3j is not Jackson serializable
    private String address;

    public AttestationRequestInternalData() {
      super();
    }

    public AttestationRequestInternalData(String description, String identifier, String address, String payload, long timeStamp) {
      super(description, payload, timestampFormat.format(new Date(timeStamp)));
      this.identifier = identifier;
      this.address = address;
    }

    public AttestationRequestInternalData(String description, String identifier, String address, String payload, String timeStamp) {
      super(description, payload, timeStamp);
      this.identifier = identifier;
      this.address = address;
    }

    public String getIdentifier() {
      return identifier;
    }

    public void setIdentifier(String identifier) {
      this.identifier = identifier;
    }

    public String getAddress() {
      return address;
    }

    public void setAddress(String address) {
      this.address = address;
    }

  }
}
