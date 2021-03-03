package org.tokenscript.eip712;

public class Eip712InternalData {
  private String description;
  private long timeStamp;

  public Eip712InternalData() {}

  public Eip712InternalData(String description, long timeStamp) {
    this.description = description;
    this.timeStamp = timeStamp;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public long getTimeStamp() {
    return timeStamp;
  }

  public void setTimeStamp(long timeStamp) {
    this.timeStamp = timeStamp;
  }

}
