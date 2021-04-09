package org.tokenscript.eip712;

import com.alphawallet.attestation.eip712.Timestamp;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ "payload", "description", "timestamp"})
public class FullEip712InternalData extends Eip712InternalData {
  private String payload;

  public FullEip712InternalData() {}

  public FullEip712InternalData(String description, String payload, Timestamp timestamp) {
    super(description, timestamp);
    this.payload = payload;
  }

  public FullEip712InternalData(String description, String payload, String timestamp) {
    super(description, timestamp);
    this.payload = payload;
  }

  public String getPayload() {
    return payload;
  }

  public void setPayload(String payload) {
    this.payload = payload;
  }

  /**
   * getSignableVersion returns a compressed version of this object that is more easily presentable to an end-user.
   * This signableVersion is the version actually signed, but the full and true version is transmitted.
   */
  @JsonIgnore
  public FullEip712InternalData getSignableVersion() {
    return new FullEip712InternalData(getDescription(), Eip712Encoder.computePayloadDigest(getPayload()), getTimestamp());
  }
}
