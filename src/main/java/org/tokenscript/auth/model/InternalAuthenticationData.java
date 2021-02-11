package org.tokenscript.auth.model;

public class InternalAuthenticationData {
  private String description;
  private String payload;
  private long timeStamp;

  public InternalAuthenticationData() {}

  public InternalAuthenticationData(String description, String payload, long timeStamp) {
    this.description = description;
    this.payload = payload;
    this.timeStamp = timeStamp;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public String getPayload() {
    return payload;
  }

  public void setPayload(String payload) {
    this.payload = payload;
  }

  public long getTimeStamp() {
    return timeStamp;
  }

  public void setTimeStamp(long timeStamp) {
    this.timeStamp = timeStamp;
  }

}