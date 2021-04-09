package org.tokenscript.eip712;

import com.alphawallet.attestation.eip712.Timestamp;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ "description", "timestamp"})
public class Eip712InternalData {
  private String description;
  private String timestamp;

  public Eip712InternalData() {}

  public Eip712InternalData(String description, String timestamp) {
    this.description = description;
    this.timestamp = timestamp;
  }

  public Eip712InternalData(String description, Timestamp timestamp) {
    this.description = description;
    this.timestamp = timestamp.getTimeAsString();
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public String getTimestamp() {
    return timestamp;
  }

  public void setTimestamp(String timestamp) {
    this.timestamp = timestamp;
  }

}
