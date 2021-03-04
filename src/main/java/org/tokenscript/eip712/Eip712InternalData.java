package org.tokenscript.eip712;

public class Eip712InternalData {
  private String description;
  private String timeStamp;

  public Eip712InternalData() {}

  public Eip712InternalData(String description, String timeStamp) {
    this.description = description;
    this.timeStamp = timeStamp;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public String getTimeStamp() {
    return timeStamp;
  }

  public void setTimeStamp(String timeStamp) {
    this.timeStamp = timeStamp;
  }

}
