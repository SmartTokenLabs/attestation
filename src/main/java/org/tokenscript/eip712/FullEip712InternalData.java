package org.tokenscript.eip712;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.Date;

public class FullEip712InternalData extends Eip712InternalData {
  private String payload;

  public FullEip712InternalData() {}

  public FullEip712InternalData(String description, String payload, long timestamp) {
    super(description, Eip712Encoder.timestampFormat.format(new Date(timestamp)));
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

  @JsonIgnore
  public FullEip712InternalData getSignableVersion() {
    return new FullEip712InternalData(getDescription(), Eip712Encoder.computePayloadDigest(getPayload()), getTimestamp());
  }
}
