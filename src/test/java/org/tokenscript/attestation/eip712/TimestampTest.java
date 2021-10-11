package org.tokenscript.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.Timestamp;

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
    StaticTime time = new StaticTime(120000);
    time.setValidity(100);
    time.setCurrentTime(109800);
    // Too new
    assertFalse(time.validateTimestamp());
    // Too old
    time.setCurrentTime(130110);
    assertFalse(time.validateTimestamp());
  }

  @Test
  public void tooLongExpiration() {
    StaticTime time = new StaticTime(100000);
    time.setValidity(990);
    time.setCurrentTime(time.getTime());
    // OG added 2s to fix 2 roundings
    long expiration = time.getTime() + 31000;
    assertFalse(time.validateAgainstExpiration(expiration));
  }

  @Test
  public void timestampInFuture() {
    StaticTime time = new StaticTime(120000);
    time.setValidity(30000);
    time.setCurrentTime(100000);
    long expiration = 130000;
    assertFalse(time.validateAgainstExpiration(expiration));
  }

  @Test
  public void timestampExpired() {
    StaticTime time = new StaticTime(100000);
    time.setValidity(50000);
    time.setCurrentTime(140000);
    long expiration = 130000;
    assertTrue(time.validateAgainstExpiration(expiration));
    expiration = 129990;
    assertFalse(time.validateAgainstExpiration(expiration));
  }

  @Test
  public void timestampFromPastOk() {
    StaticTime time = new StaticTime(100000);
    time.setValidity(30000);
    time.setCurrentTime(110000);
    long expiration = 120000;
    assertTrue(time.validateAgainstExpiration(expiration));
  }

  @Test
  public void validForTooLong() {
    StaticTime time = new StaticTime(100000);
    time.setValidity(20000);
    long expiration = 120010;
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
