package com.alphawallet.attestation.core;

import com.alphawallet.attestation.ValidationTools;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Arrays;

public class Nonce {
  public static byte[] makeNonce(String senderIdentifier, String address, String receiverIdentifier, long timestampInMs) {
    return makeNonce(senderIdentifier, address, receiverIdentifier, new byte[0], timestampInMs);
  }

  public static byte[] makeNonce(String userIdentifier, String address, String receiverIdentifier, byte[] otherData, long timestampInMs) {
    // Ensure that the address is valid, since this will throw an exception if not
    if (!ValidationTools.isAddress(address)) {
      throw new IllegalArgumentException("Address is not valid");
    }
    ByteBuffer buffer = ByteBuffer
        .allocate(Long.BYTES + 3 * AttestationCrypto.BYTES_IN_DIGEST + ValidationTools.ADDRESS_LENGTH_IN_BYTES);
    buffer.putLong(timestampInMs);
    // Hash to ensure all variable length components is encoded with constant length
    buffer.put(AttestationCrypto.hashWithKeccak(userIdentifier.getBytes(StandardCharsets.UTF_8)));
    buffer.put(address.getBytes(StandardCharsets.UTF_8));
    buffer.put(AttestationCrypto.hashWithKeccak(receiverIdentifier.getBytes(StandardCharsets.UTF_8)));
    buffer.put(AttestationCrypto.hashWithKeccak(otherData));
    return buffer.array();
  }

  public static boolean validateNonce(byte[] nonce, String senderIdentifier, String address,
      String receiverIdentifier, long timestampSlack) {
    return validateNonce(nonce, senderIdentifier, address, receiverIdentifier, timestampSlack, new byte[0]);
  }

  public static boolean validateNonce(byte[] nonce, String senderIdentifier,
      String address, String receiverIdentifier, long timestampSlack, byte[] otherData) {
    long currentTime = Clock.systemUTC().millis();
    if (!ValidationTools.validateTimestamp(getTimestamp(nonce), currentTime, timestampSlack)) {
      return false;
    }
    if (!validateSenderIdentifier(nonce, senderIdentifier)) {
      return false;
    }
    if (!validateAddress(nonce, address)) {
      return false;
    }
    if (!validateReceiverIdentifier(nonce, receiverIdentifier)) {
      return false;
    }
    if (!validateOtherData(nonce, otherData)) {
      return false;
    }

    return true;
  }

  static boolean validateSenderIdentifier(byte[] nonce, String senderIdentifier) {
    byte[] senderIdentifierDigest = Arrays.copyOfRange(nonce, Long.BYTES,
        Long.BYTES + AttestationCrypto.BYTES_IN_DIGEST);
    byte[] recomputedSenderIdentifierDigest = AttestationCrypto.hashWithKeccak(
        senderIdentifier.getBytes(StandardCharsets.UTF_8));
    return Arrays.equals(senderIdentifierDigest, recomputedSenderIdentifierDigest);
  }

  static boolean validateAddress(byte[] nonce, String address) {
    byte[] referenceAddress = Arrays.copyOfRange(nonce, Long.BYTES + AttestationCrypto.BYTES_IN_DIGEST,
        Long.BYTES + AttestationCrypto.BYTES_IN_DIGEST + ValidationTools.ADDRESS_LENGTH_IN_BYTES);
    if (!ValidationTools.isAddress(address)) {
      throw new IllegalArgumentException("Address is not valid");
    }
    byte[] recomputedKeyDigest = address.getBytes(StandardCharsets.UTF_8);
    return Arrays.equals(referenceAddress, recomputedKeyDigest);
  }

  static boolean validateReceiverIdentifier(byte[] nonce, String receiverIdentifier) {
    byte[] receiverIdentifierDigest = Arrays.copyOfRange(nonce,
        Long.BYTES + AttestationCrypto.BYTES_IN_DIGEST + ValidationTools.ADDRESS_LENGTH_IN_BYTES,
        Long.BYTES + 2 * AttestationCrypto.BYTES_IN_DIGEST + ValidationTools.ADDRESS_LENGTH_IN_BYTES);
    byte[] recomputedReceiverIdentifierDigest = AttestationCrypto.hashWithKeccak(
        receiverIdentifier.getBytes(StandardCharsets.UTF_8));
    return Arrays.equals(receiverIdentifierDigest, recomputedReceiverIdentifierDigest);
  }

  static boolean validateOtherData(byte[] nonce, byte[] otherData) {
    byte[] receiverOtherData = Arrays.copyOfRange(nonce,
        Long.BYTES + 2 * AttestationCrypto.BYTES_IN_DIGEST + ValidationTools.ADDRESS_LENGTH_IN_BYTES,
        Long.BYTES + 3 * AttestationCrypto.BYTES_IN_DIGEST + ValidationTools.ADDRESS_LENGTH_IN_BYTES);
    byte[] recomputedReceiverOtherData = AttestationCrypto.hashWithKeccak(otherData);
    return Arrays.equals(receiverOtherData, recomputedReceiverOtherData);
  }

  static long getTimestamp(byte[] nonce) {
    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
    buffer.put(Arrays.copyOfRange(nonce, 0, Long.BYTES));
    buffer.flip();
    return buffer.getLong();
  }

}
