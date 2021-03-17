package com.alphawallet.attestation.eip712;

import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import org.tokenscript.eip712.Eip712Encoder;
import org.tokenscript.eip712.FullEip712InternalData;

public class Eip712AttestationRequestEncoder extends Eip712Encoder {
  static final String PROTOCOL_VERSION = "0.1";

  static final String PRIMARY_NAME = "AttestationRequest";
  static final String USAGE_VALUE = "Linking Ethereum address to phone or email";

  public Eip712AttestationRequestEncoder(long chainId) {
    super(PROTOCOL_VERSION, PRIMARY_NAME, chainId);
  }

  public HashMap<String, List<Entry>> getTypes() {
    HashMap<String, List<Entry>> types = getDefaultTypes();
    types.get(PRIMARY_NAME).add(ADDRESS_ENTRY);
    types.get(PRIMARY_NAME).add(IDENTIFIER_ENTRY);
    return types;
  }

  static class AttestationRequestInternalData extends FullEip712InternalData {
    private String identifier;
    // TODO This should actually be of type Address, but currently this type of the web3j is not Jackson serializable
    private String address;

    public AttestationRequestInternalData() {
      super();
    }

    public AttestationRequestInternalData(String description, String identifier, String address, String payload, long timestamp) {
      super(description, payload, timestampFormat.format(new Date(timestamp)));
      this.identifier = identifier;
      this.address = address;
    }

    public AttestationRequestInternalData(String description, String identifier, String address, String payload, String timestamp) {
      super(description, payload, timestamp);
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

    @JsonIgnore
    @Override
    public AttestationRequestInternalData getSignableVersion() {
      return new AttestationRequestInternalData(getDescription(), getIdentifier(), getAddress(), Eip712Encoder.computePayloadDigest(getPayload()), getTimestamp());
    }
  }

}
