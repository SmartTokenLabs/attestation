package com.alphawallet.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class TimestampTest {

  @Test
  public void invalidTimestamp() {
    // Does not contain timezone
    assertThrows( RuntimeException.class, ()-> new Timestamp("1970.01.01 at 01:00:00"));
  }

  @Test
  public void consistency() {
    Timestamp time = new Timestamp(9999);
    assertEquals(9000, time.getTime());
    Timestamp otherTimestamp = new Timestamp(time.getTimeAsString());
    assertEquals(9000, otherTimestamp.getTime());
  }

  @Test
  public void slackConsistency() {
    Timestamp time = new Timestamp(9999);
    time.setValidity(10);
    assertEquals(10, time.getValidity());
  }

  @Test
  public void validateTimestamp() {
    Timestamp time = new Timestamp();
    time.setValidity(10);
    assertTrue(time.validateTimestamp());
  }

  @Test
  public void negativeTimestampTest() {
    StaticTime time = new StaticTime(12000);
    time.setValidity(10);
    time.setCurrentTime(10980);
    // Too new
    assertFalse(time.validateTimestamp());
    // Too old
    time.setCurrentTime(13011);
    assertFalse(time.validateTimestamp());
  }

  @Test
  public void tooLongExpiration() {
    StaticTime time = new StaticTime(10000);
    time.setValidity(99);
    time.setCurrentTime(time.getTime());
    long expiration = time.getTime() + 1100;
    assertFalse(time.validateAgainstExpiration(expiration));
  }

  @Test
  public void timestampInFuture() {
    StaticTime time = new StaticTime(12000);
    time.setValidity(3000);
    time.setCurrentTime(10000);
    long expiration = 13000;
    assertFalse(time.validateAgainstExpiration(expiration));
  }

  @Test
  public void timestampExpired() {
    StaticTime time = new StaticTime(10000);
    time.setValidity(5000);
    time.setCurrentTime(14000);
    long expiration = 13000;
    assertTrue(time.validateAgainstExpiration(expiration));
    expiration = 12999;
    assertFalse(time.validateAgainstExpiration(expiration));
  }

  @Test
  public void timestampFromPastOk() {
    StaticTime time = new StaticTime(10000);
    time.setValidity(3000);
    time.setCurrentTime(11000);
    long expiration = 12000;
    assertTrue(time.validateAgainstExpiration(expiration));
  }

  @Test
  public void validForTooLong() {
    StaticTime time = new StaticTime(10000);
    time.setValidity(2000);
    long expiration = 12001;
    assertFalse(time.validateAgainstExpiration(expiration));
  }

  private class StaticTime extends Timestamp {
    private long currentTime;
    public StaticTime(long time) {
      super(time);
    }

    public void setCurrentTime(long time)  {
      currentTime = time;
    }
    @Override
    protected long getCurrentTime() {
      return currentTime;
    }
  }
}
