package org.tokenscript.eip712;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.Date;

public class FullEip712InternalData extends Eip712InternalData {
  private String payload;

  public FullEip712InternalData() {}

  public FullEip712InternalData(String description, String payload, long timeStamp) {
    super(description, Eip712Encoder.timestampFormat.format(new Date(timeStamp)));
    this.payload = payload;
  }

  public FullEip712InternalData(String description, String payload, String timeStamp) {
    super(description, timeStamp);
    this.payload = payload;
  }

  public String getPayload() {
    return payload;
  }

  public void setPayload(String payload) {
    this.payload = payload;
  }

  @JsonIgnore
  public SignableEip712InternalData getSignableVersion() {
    return new SignableEip712InternalData(this);
  }
}
