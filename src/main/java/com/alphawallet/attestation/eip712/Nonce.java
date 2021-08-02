package com.alphawallet.attestation.eip712;

import com.alphawallet.attestation.ValidationTools;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.ExceptionUtil;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Nonce {
  private static final Logger logger = LogManager.getLogger(Nonce.class);

  public static final long DEFAULT_NONCE_TIME_LIMIT_MS = 1000*60*20; // 20 min

  private static final int senderAddressIndexStart = 0;
  private static final int senderAddressIndexStop = ValidationTools.ADDRESS_LENGTH_IN_BYTES;
  private static final int receiverIdentifierIndexStart = senderAddressIndexStop;
  private static final int receiverIdentifierIndexStop = receiverIdentifierIndexStart + AttestationCrypto.BYTES_IN_DIGEST;
  private static final int timestampIndexStart = receiverIdentifierIndexStop;
  private static final int timestampIndexStop = timestampIndexStart + Long.BYTES;
  private static final int otherDataIndexStart = timestampIndexStop;

  public static byte[] makeNonce(String senderAddress, String receiverIdentifier, Timestamp timestamp) {
    return makeNonce(senderAddress, receiverIdentifier, timestamp, new byte[0]);
  }

  public static byte[] makeNonce(String senderAddress, String receiverIdentifier, Timestamp timestamp, byte[] otherData) {
    // Ensure that the address is valid, since this will throw an exception if not
    if (!ValidationTools.isAddress(senderAddress)) {
      throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Address is not valid"));
    }
    ByteBuffer buffer = ByteBuffer.allocate(otherDataIndexStart + otherData.length);
    // Hash to ensure all variable length components is encoded with constant length
    buffer.put(senderAddress.toUpperCase().getBytes(StandardCharsets.UTF_8));
    buffer.put(AttestationCrypto.hashWithKeccak(receiverIdentifier.getBytes(StandardCharsets.UTF_8)));
    buffer.put(longToBytes(timestamp.getTime()));
    buffer.put(otherData);
    return buffer.array();
  }

  public static boolean validateNonce(byte[] nonce, String senderAddress,
      String receiverIdentifier, Timestamp minTime, Timestamp maxTime) {
    return validateNonce(nonce, senderAddress, receiverIdentifier, minTime, maxTime, new byte[0]);
  }

  public static boolean validateNonce(byte[] nonce,
      String senderAddress, String receiverIdentifier, Timestamp minTime, Timestamp maxTime, byte[] otherData) {
    if (!validateAddress(nonce, senderAddress)) {
      logger.error("Could not validate address");
      return false;
    }
    if (!validateReceiverIdentifier(nonce, receiverIdentifier)) {
      logger.error("Receiver identifier incorrect");
      return false;
    }
    if (!validateTimestamp(nonce, minTime, maxTime)) {
      logger.error("Could not validate time stamp");
      return false;
    }
    if (!validateOtherData(nonce, otherData)) {
      logger.error("Could not validate auxiliary data");
      return false;
    }
    return true;
  }

  static boolean validateAddress(byte[] nonce, String address) {
    byte[] referenceAddress = Arrays.copyOfRange(nonce, senderAddressIndexStart, senderAddressIndexStop);
    if (!ValidationTools.isAddress(address)) {
      throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Address is not valid"));
    }
    byte[] recomputedKeyDigest = address.toUpperCase().getBytes(StandardCharsets.UTF_8);
    return Arrays.equals(referenceAddress, recomputedKeyDigest);
  }

  static boolean validateReceiverIdentifier(byte[] nonce, String receiverIdentifier) {
    byte[] receiverIdentifierDigest = Arrays.copyOfRange(nonce, receiverIdentifierIndexStart, receiverIdentifierIndexStop);
    byte[] recomputedReceiverIdentifierDigest = AttestationCrypto.hashWithKeccak(
        receiverIdentifier.getBytes(StandardCharsets.UTF_8));
    return Arrays.equals(receiverIdentifierDigest, recomputedReceiverIdentifierDigest);
  }

  static boolean validateTimestamp(byte[] nonce, Timestamp minTime, Timestamp maxTime) {
    long timestamp = bytesToLong(Arrays.copyOfRange(nonce, timestampIndexStart, timestampIndexStop));
    Timestamp nonceStamp = new Timestamp(timestamp);
    nonceStamp.setValidity(maxTime.getTime()-minTime.getTime());
    return nonceStamp.validateAgainstExpiration(maxTime.getTime());
  }

  static boolean validateOtherData(byte[] nonce, byte[] otherData) {
    byte[] receiverOtherData = Arrays.copyOfRange(nonce,
         otherDataIndexStart, otherDataIndexStart + otherData.length);
    return Arrays.equals(receiverOtherData, otherData);
  }

  public static byte[] longToBytes(long input) {
    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
    buffer.putLong(input);
    return buffer.array();
  }

  public static long bytesToLong(byte[] input) {
    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
    buffer.put(Arrays.copyOfRange(input, 0, Long.BYTES));
    buffer.flip();
    return buffer.getLong();
  }

  public static Timestamp getTimestamp(byte[] nonce) {
    return new Timestamp(bytesToLong(Arrays.copyOfRange(nonce, timestampIndexStart, timestampIndexStop)));
  }

}
