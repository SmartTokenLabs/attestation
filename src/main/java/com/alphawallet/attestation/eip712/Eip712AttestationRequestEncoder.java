package com.alphawallet.attestation.eip712;

import com.alphawallet.token.web.Ethereum.web3j.StructuredData.Entry;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.HashMap;
import java.util.List;
import org.tokenscript.eip712.Eip712Encoder;
import org.tokenscript.eip712.FullEip712InternalData;

public class Eip712AttestationRequestEncoder extends Eip712Encoder {
  private static final Entry IDENTIFIER_ENTRY = new Entry("identifier", STRING);

  private static final String PROTOCOL_VERSION = "0.1";
  private static final String PRIMARY_NAME = "AttestationRequest";
  private static final String USAGE_VALUE = "Linking Ethereum address to phone or email";

  public Eip712AttestationRequestEncoder() {
    super(USAGE_VALUE, PROTOCOL_VERSION, PRIMARY_NAME);
  }

  public HashMap<String, List<Entry>> getTypes() {
    HashMap<String, List<Entry>> types = getDefaultTypes();
    types.get(PRIMARY_NAME).add(IDENTIFIER_ENTRY);
    return types;
  }

  @JsonPropertyOrder({ "payload", "description", "timestamp", "identifier"})
  static class AttestationRequestInternalData extends FullEip712InternalData {
    private String identifier;

    public AttestationRequestInternalData() {
      super();
    }

    public AttestationRequestInternalData(String description, String identifier,
        String payload, Timestamp timestamp) {
      super(description, payload, timestamp);
      this.identifier = identifier;
    }

    public AttestationRequestInternalData(String description, String identifier,
        String payload, String timestamp) {
      super(description, payload, timestamp);
      this.identifier = identifier;
    }

    public String getIdentifier() {
      return identifier;
    }

    public void setIdentifier(String identifier) {
      this.identifier = identifier;
    }

    @JsonIgnore
    @Override
    public AttestationRequestInternalData getSignableVersion() {
      return new AttestationRequestInternalData(getDescription(), getIdentifier(), Eip712Encoder.computePayloadDigest(getPayload()), getTimestamp());
    }
  }

}
