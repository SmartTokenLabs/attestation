package org.devcon.ticket;

import com.alphawallet.attestation.core.ExceptionUtil;
import com.alphawallet.attestation.core.URLUtility;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.tokenscript.eip712.Eip712Common;

public class UnpredictibleNumberTool {
  private static final Logger logger = LogManager.getLogger(UnpredictibleNumberTool.class);
  public static final long DEFAULT_VALIDITY_IN_MS = 3600*1000;
  public static final int BYTES_IN_UN = 8; // 64 bits

  private static final ByteBuffer longBuffer = ByteBuffer.allocate(Long.BYTES);
  private final String domain;
  private final long validityInMs;
  private final HMac hmac = new HMac(new KeccakDigest(256));

  public UnpredictibleNumberTool(byte[] key, String domain) {
    this(key, domain, DEFAULT_VALIDITY_IN_MS);
  }

  public String getDomain() {
    return domain;
  }

  public UnpredictibleNumberTool(byte[] key, String domain, long validityInMs) {
    this.domain = domain.toLowerCase();
    this.validityInMs = validityInMs;
    hmac.init(new KeyParameter(key));
    // todo should be moved to url utility
    if (!Eip712Common.isDomainValid(domain)) {
      throw new IllegalArgumentException("Domain is not a valid domain");
    }
  }

  /**
   * Computes an URL friendly base 64 encoding of HMAC(expirationInMs || domain).
   * The encoding consists of BYTES_IN_UN bytes
   * ExpirationInMs is computed from current time plus DEFAULT_VALIDITY_IN_MS
   */
  public UnpredictableNumberBundle getUnpredictableNumberBundle() {
    long expiration = Clock.systemUTC().millis() + validityInMs;
    return new UnpredictableNumberBundle(getUnpredictableNumber(expiration), domain, expiration);
  }

  private String getUnpredictableNumber(long expirationInMs) {
    hmac.reset();
    hmac.update(longToBytes(expirationInMs), 0, Long.BYTES);
    hmac.update(domain.getBytes(StandardCharsets.UTF_8), 0, domain.getBytes(StandardCharsets.UTF_8).length);
    byte[] digest = new byte[256 / 8];
    hmac.doFinal(digest, 0);
    byte[] result = new byte[BYTES_IN_UN];
    System.arraycopy(digest, 0, result, 0, BYTES_IN_UN);
    return URLUtility.encodeData(result);
  }

  public boolean validateUnpredictableNumber(String un, long expirationInMs) {
    if (Clock.systemUTC().millis() > expirationInMs) {
      logger.error("Unpredictable number has expired");
      return false;
    }
    String expectedNumber = getUnpredictableNumber(expirationInMs);
    if (!expectedNumber.equals(un)) {
      logger.error("The unpredictable number is computed incorrectly. Either wrong key or wrong domain");
      return false;
    }
    return true;
  }

  private static byte[] longToBytes(long x) {
    longBuffer.putLong(0, x);
    return longBuffer.array();
  }

  private static long bytesToLong(byte[] bytes) {
    if (bytes.length != Long.BYTES) {
      ExceptionUtil.throwException(logger, new IllegalArgumentException("Long input not of expected length"));
    }
    longBuffer.put(bytes, 0, Long.BYTES);
    longBuffer.flip(); //need flip
    return longBuffer.getLong();
  }
}
