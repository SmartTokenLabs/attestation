package com.alphawallet.attestation.core;

import com.alphawallet.attestation.ValidationTools;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Nonce {
  // This must be as large as the possible rounding
  public static final int TIMESTAMP_SLACK_MS = 1000;

  private static final int senderAddressIndexStart = 0;
  private static final int senderAddressIndexStop = ValidationTools.ADDRESS_LENGTH_IN_BYTES;
  private static final int receiverIdentifierIndexStart = senderAddressIndexStop;
  private static final int receiverIdentifierIndexStop = receiverIdentifierIndexStart + AttestationCrypto.BYTES_IN_DIGEST;
  private static final int timestampIndexStart = receiverIdentifierIndexStop;
  private static final int timestampIndexStop = timestampIndexStart + Long.BYTES;
  private static final int otherDataIndexStart = timestampIndexStop;

  public static byte[] makeNonce(String senderAddress, String receiverIdentifier, long timestamp) {
    return makeNonce(senderAddress, receiverIdentifier, timestamp, new byte[0]);
  }

  public static byte[] makeNonce(String senderAddress, String receiverIdentifier, long timestamp, byte[] otherData) {
    // Ensure that the address is valid, since this will throw an exception if not
    if (!ValidationTools.isAddress(senderAddress)) {
      throw new IllegalArgumentException("Address is not valid");
    }
    ByteBuffer buffer = ByteBuffer.allocate(otherDataIndexStart + otherData.length);
    // Hash to ensure all variable length components is encoded with constant length
    buffer.put(senderAddress.getBytes(StandardCharsets.UTF_8));
    buffer.put(AttestationCrypto.hashWithKeccak(receiverIdentifier.getBytes(StandardCharsets.UTF_8)));
    buffer.put(longToBytes(timestamp));
    buffer.put(otherData);
    return buffer.array();
  }

  public static boolean validateNonce(byte[] nonce, String senderAddress,
      String receiverIdentifier, long minTime, long maxTime) {
    return validateNonce(nonce, senderAddress, receiverIdentifier, minTime, maxTime, new byte[0]);
  }

  public static boolean validateNonce(byte[] nonce,
      String senderAddress, String receiverIdentifier, long minTime, long maxTime, byte[] otherData) {
    if (!validateAddress(nonce, senderAddress)) {
      return false;
    }
    if (!validateReceiverIdentifier(nonce, receiverIdentifier)) {
      return false;
    }
    if (!validateTimestamp(nonce, minTime, maxTime)) {
      return false;
    }
    if (!validateOtherData(nonce, otherData)) {
      return false;
    }
    return true;
  }

  static boolean validateAddress(byte[] nonce, String address) {
    byte[] referenceAddress = Arrays.copyOfRange(nonce, senderAddressIndexStart, senderAddressIndexStop);
    if (!ValidationTools.isAddress(address)) {
      throw new IllegalArgumentException("Address is not valid");
    }
    byte[] recomputedKeyDigest = address.getBytes(StandardCharsets.UTF_8);
    return Arrays.equals(referenceAddress, recomputedKeyDigest);
  }

  static boolean validateReceiverIdentifier(byte[] nonce, String receiverIdentifier) {
    byte[] receiverIdentifierDigest = Arrays.copyOfRange(nonce, receiverIdentifierIndexStart, receiverIdentifierIndexStop);
    byte[] recomputedReceiverIdentifierDigest = AttestationCrypto.hashWithKeccak(
        receiverIdentifier.getBytes(StandardCharsets.UTF_8));
    return Arrays.equals(receiverIdentifierDigest, recomputedReceiverIdentifierDigest);
  }

  static boolean validateTimestamp(byte[] nonce, long minTime, long maxTime) {
    long timestamp = bytesToLong(Arrays.copyOfRange(nonce, timestampIndexStart, timestampIndexStop));
    if (timestamp < minTime - TIMESTAMP_SLACK_MS) {
      return false;
    }
    if (timestamp > maxTime + TIMESTAMP_SLACK_MS) {
      return false;
    }
    return true;
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

  public static long getTimestamp(byte[] nonce) {
    return bytesToLong(Arrays.copyOfRange(nonce, timestampIndexStart, timestampIndexStop));
  }

}
