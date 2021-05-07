package com.alphawallet.attestation.eip712;


import com.alphawallet.attestation.core.ExceptionUtil;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Clock;
import java.util.Date;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Timestamp {
  private static final Logger logger = LogManager.getLogger(Timestamp.class);

  public static final int ALLOWED_ROUNDING = 1000; // 1 sec, since we are always rounding to the nearest second in the string representation
  // Timestamp with millisecond accuracy and timezone info
  public static final SimpleDateFormat TIMESTAMP_FORMAT = new SimpleDateFormat("EEE MMM d yyyy HH:mm:ss 'GMT'Z", Locale.US);

  // See RFC 5282, https://tools.ietf.org/html/rfc5280#section-4.1.2.5, based on the GeneralizedTime value of 99991231235959Z
  public static final long UNLIMITED = 253402297199000L;
  public static final long DEFAULT_TOKEN_TIME_LIMIT = 1000 * 60 * 60 * 24 * 365; // 1 year
  public static final long DEFAULT_TIME_LIMIT_MS = 1000*60*20; // 20 minutes

  private final long time;
  private long validity = 0;

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

  public long getTime() {
    return time;
  }

  public String getTimeAsString() {
    return Timestamp.TIMESTAMP_FORMAT.format(new Date(time));
  }

  public boolean validateTimestamp() {
    long currentTime = getCurrentTime();
    if (time > currentTime + ALLOWED_ROUNDING) {
      logger.error("Timestamp is from the future");
      return false;
    }
    // Slack only goes into the future
    if (time < currentTime - ALLOWED_ROUNDING - validity) {
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
    if (expirationTimeInMs < currentTime - ALLOWED_ROUNDING) {
      logger.error("Expiration time has passed");
      return false;
    }
    // If the token is valid for too long
    if (expirationTimeInMs - time > validity + ALLOWED_ROUNDING) {
      logger.error("Lifetime is larger than allowed");
      return false;
    }
    return true;
  }

  public static long stringTimestampToLong(String timestamp) {
    try {
      return TIMESTAMP_FORMAT.parse(timestamp).getTime();
    } catch (ParseException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode timestamp", e);
    }
  }

  protected long getCurrentTime() {
    return Clock.systemUTC().millis();
  }
}
