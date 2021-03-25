package com.alphawallet.attestation.eip712;

import com.alphawallet.attestation.ValidationTools;
import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import org.tokenscript.eip712.Eip712Encoder;
import org.tokenscript.eip712.FullEip712InternalData;

public class Eip712AttestationRequestEncoder extends Eip712Encoder {
  private static final Entry ADDRESS_ENTRY = new Entry("address", STRING);
  private static final Entry IDENTIFIER_ENTRY = new Entry("identifier", STRING);

  private static final String PROTOCOL_VERSION = "0.1";
  private static final String PRIMARY_NAME = "AttestationRequest";
  private static final String USAGE_VALUE = "Linking Ethereum address to phone or email";

  public Eip712AttestationRequestEncoder() {
    super(USAGE_VALUE, PROTOCOL_VERSION, PRIMARY_NAME);
  }

  public HashMap<String, List<Entry>> getTypes() {
    HashMap<String, List<Entry>> types = getDefaultTypes();
    types.get(PRIMARY_NAME).add(ADDRESS_ENTRY);
    types.get(PRIMARY_NAME).add(IDENTIFIER_ENTRY);
    return types;
  }

  @JsonPropertyOrder({ "payload", "description", "timestamp", "address", "identifier"})
  static class AttestationRequestInternalData extends FullEip712InternalData {
    // TODO This should actually be of type Address, but currently this type of the web3j is not Jackson serializable
    private String address;
    private String identifier;

    public AttestationRequestInternalData() {
      super();
    }

    public AttestationRequestInternalData(String description, String identifier, String address, String payload, long timestamp) {
      super(description, payload, TIMESTAMP_FORMAT.format(new Date(timestamp)));
      testAddress(address);
      this.address = address;
      this.identifier = identifier;
    }

    public AttestationRequestInternalData(String description, String identifier, String address, String payload, String timestamp) {
      super(description, payload, timestamp);
      testAddress(address);
      this.address = address;
      this.identifier = identifier;
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

    @JsonIgnore
    private void testAddress(String address) {
      if (!ValidationTools.isNullOrAddress(address)) {
        throw new RuntimeException("Not a valid address");
      }
    }
    @JsonIgnore
    @Override
    public AttestationRequestInternalData getSignableVersion() {
      return new AttestationRequestInternalData(getDescription(), getIdentifier(), getAddress(), Eip712Encoder.computePayloadDigest(getPayload()), getTimestamp());
    }
  }

}
