package org.tokenscript.attestation.core;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.tokenscript.eip712.Eip712Common;

public class UNMac implements UnpredictableNumberTool {

  public static final int BYTES_IN_UN = 16; // 128 bits
  private static final Logger logger = LogManager.getLogger(UNMac.class);

  private final SecureRandom random;
  private final String domain;
  private final long validityInMs;
  private final HMac hmac = new HMac(new SHA3Digest(BYTES_IN_SEED * 8));

  public UNMac(byte[] key, String domain) {
    this(new SecureRandom(), key, domain);
  }

  public UNMac(SecureRandom random, byte[] key, String domain) {
    this(random, key, domain, DEFAULT_VALIDITY_IN_MS);
  }

  public UNMac(SecureRandom random, byte[] key, String domain, long validityInMs) {
    this.random = random;
    this.domain = domain;
    this.validityInMs = validityInMs;
    hmac.init(new KeyParameter(key));
    // todo should be moved to url utility
    if (!Eip712Common.isDomainValid(domain)) {
      throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Domain is not a valid domain"));
    }
  }

  @Override
  public String getDomain() {
    return domain;
  }

  @Override
  public UnpredictableNumberBundle getUnpredictableNumberBundle() {
    return getUnpredictableNumberBundle(null);
  }


  @Override
  public UnpredictableNumberBundle getUnpredictableNumberBundle(byte[] context) {
    long expiration = Clock.systemUTC().millis() + validityInMs;
    byte[] randomness = random.generateSeed(BYTES_IN_SEED);
    // Construct UN of BYTES_IN_UN bytes
    return new UnpredictableNumberBundle(
        getUnpredictableNumber(randomness, expiration, context, BYTES_IN_UN)
        , randomness, domain, expiration, context);
  }

  private String getUnpredictableNumber(byte[] randomness, long expirationInMs, byte[] context,
      int unSize) {
    // compute HMAC on the expiration, randomness and the hash digest of the context
    hmac.reset();
    hmac.update(UnpredictableNumberTool.longToBytes(expirationInMs), 0, Long.BYTES);
    hmac.update(randomness, 0, BYTES_IN_SEED);
    if (context != null) {
      hmac.update(UnpredictableNumberTool.hashContext(context), 0, BYTES_IN_SEED);
    }
    hmac.update(domain.getBytes(StandardCharsets.UTF_8), 0,
        domain.getBytes(StandardCharsets.UTF_8).length);
    byte[] digest = new byte[BYTES_IN_SEED];
    hmac.doFinal(digest, 0);
    byte[] result = new byte[unSize];
    System.arraycopy(digest, 0, result, 0, unSize);
    return URLUtility.encodeData(result);
  }

  @Override
  public boolean validateUnpredictableNumber(String un, byte[] randomness, long expirationInMs) {
    return validateUnpredictableNumber(un, randomness, expirationInMs, null);
  }

  @Override
  public boolean validateUnpredictableNumber(String un, byte[] randomness, long expirationInMs, byte[] context) {
    if (Clock.systemUTC().millis() > expirationInMs) {
      logger.error("Unpredictable number has expired");
      return false;
    }
    int unByteLength = URLUtility.decodeData(un).length;
    String expectedNumber = getUnpredictableNumber(randomness, expirationInMs, context,
        unByteLength);
    if (!expectedNumber.equals(un)) {
      logger.error(
          "The unpredictable number is computed incorrectly. Either wrong key or wrong domain");
      return false;
    }
    return true;
  }
}
