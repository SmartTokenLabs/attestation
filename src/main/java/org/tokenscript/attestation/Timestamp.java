package org.tokenscript.attestation;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.tokenscript.attestation.core.ExceptionUtil;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Clock;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

public class Timestamp {
  private static final Logger logger = LogManager.getLogger(Timestamp.class);

  public static final int ALLOWED_ROUNDING = 20000; // 10 sec to account for both rounding down to nearest second and remote clock issues
                                                    // JB - Extend this to 20 seconds so we can create an attestation that is invalid within the current Ethereum block

  // See RFC 5282, https://tools.ietf.org/html/rfc5280#section-4.1.2.5, based on the GeneralizedTime value of 99991231235959Z
  public static final long UNLIMITED = 253402297199000L;
  public static final long DEFAULT_TOKEN_TIME_LIMIT = 1000L * 60 * 60 * 24 * 365; // 1 year
  public static final long DEFAULT_TIME_LIMIT_MS = 1000L*60*20; // 20 minutes

  private final long time;
  private long validity = 0;

  // Timestamp with millisecond accuracy and timezone info
  public static final SimpleDateFormat getTimestampFormat() {
    SimpleDateFormat format = new SimpleDateFormat("EEE MMM d yyyy HH:mm:ss 'GMT'Z", Locale.US);
    format.setTimeZone(TimeZone.getTimeZone("UTC"));
    return format;
  }

  public Timestamp() {
    long tempTime = getCurrentTime();
    // Round down to nearest second
    this.time = tempTime - (tempTime % 1000);
  }

  public Timestamp(long timeSinceEpochInMs) {
    // Round down to nearest second
    this.time = timeSinceEpochInMs - (timeSinceEpochInMs % 1000);
  }

  public Timestamp(String timeAsString) {
    this.time = stringTimestampToLong(timeAsString);
  }

  public long getValidity() {
    return validity;
  }

  public void setValidity(long validity) {
    this.validity = validity;
  }

  /**
   * Returns time in milliseconds
   */
  public long getTime() {
    return time;
  }

  public String getTimeAsString() {
    return Timestamp.getTimestampFormat().format(new Date(time));
  }

  public boolean validateTimestamp() {
    long currentTime = getCurrentTime();
    if (time > currentTime + ALLOWED_ROUNDING) {
      logger.error("Timestamp is from the future");
      return false;
    }
    // Slack only goes into the future
    if (time + validity + ALLOWED_ROUNDING < currentTime) {
      logger.error("Timestamp is expired");
      return false;
    }
    return true;
  }

  public boolean validateAgainstExpiration(long expirationTimeInMs) {
    long currentTime = getCurrentTime();
    // If timestamp is in the future
    if (time > currentTime + ALLOWED_ROUNDING) {
      logger.error("Timestamp is from the future");
      return false;
    }
    // If token has expired
    long diff = (currentTime - ALLOWED_ROUNDING) - expirationTimeInMs;
    if (expirationTimeInMs < currentTime - ALLOWED_ROUNDING) {
      logger.error("Expiration time has passed");
      return false;
    }
    // If the token is valid for too long
    // OG added 2 * ALLOWED_ROUNDING extra time to fix roundings
    if (expirationTimeInMs - time > validity + ALLOWED_ROUNDING) {
      logger.error("Lifetime is larger than allowed");
      return false;
    }
    return true;
  }

  public static long stringTimestampToLong(String timestamp) {
    try {
      return getTimestampFormat().parse(timestamp).getTime();
    } catch (ParseException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode timestamp", e);
    }
  }

  public long getCurrentTime() {
    return Clock.systemUTC().millis();
  }
}
