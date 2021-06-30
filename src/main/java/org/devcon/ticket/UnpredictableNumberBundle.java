package org.devcon.ticket;


import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ "number", "domain", "expiration"})
public class UnpredictableNumberBundle {
  private String number;
  private String domain;
  private long expiration;

  public UnpredictableNumberBundle() {}

  public UnpredictableNumberBundle(String number, String domain, long expiration) {
    this.number = number;
    this.domain = domain;
    this.expiration = expiration;
  }

  public String getNumber() {
    return number;
  }

  public void setNumber(String number) {
    this.number = number;
  }

  public String getDomain() {
    return domain;
  }

  public void setDomain(String domain) {
    this.domain = domain;
  }

  public long getExpiration() {
    return expiration;
  }

  public void setExpiration(long expiration) {
    this.expiration = expiration;
  }
}
