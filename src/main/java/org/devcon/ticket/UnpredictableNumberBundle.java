package org.devcon.ticket;


public class UnpredictableNumberBundle {
  private final String number;
  private final String domain;
  private final long expiration;

  public UnpredictableNumberBundle(String number, String domain, long expiration) {
    this.number = number;
    this.domain = domain;
    this.expiration = expiration;
  }

  public String getNumber() {
    return number;
  }

  public String getDomain() {
    return domain;
  }

  public long getExpiration() {
    return expiration;
  }
}
