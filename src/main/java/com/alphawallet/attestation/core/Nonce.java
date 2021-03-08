package com.alphawallet.attestation.core;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Arrays;
import org.web3j.abi.datatypes.Address;

public class Nonce {
  public static final long TIMESTAMP_SLACK_MS = 60000L; // 1 minute

  public static byte[] makeNonce(String senderIdentifier, String address, String receiverIdentifier, long timestampInMs) {
    return makeNonce(senderIdentifier, address, receiverIdentifier, new byte[0], timestampInMs);
  }

  public static byte[] makeNonce(String userIdentifier, String address, String receiverIdentifier, byte[] otherData, long timestampInMs) {
    ByteBuffer buffer = ByteBuffer
        .allocate(Long.BYTES + 3 * AttestationCrypto.BYTES_IN_DIGEST + (Address.DEFAULT_LENGTH/8));
    buffer.putLong(timestampInMs);
    // Hash to ensure all variable length components is encoded with constant length
    buffer.put(AttestationCrypto.hashWithKeccak(userIdentifier.getBytes(StandardCharsets.UTF_8)));
    // Ensure that the address is valid, since this will throw an exception if not
    buffer.put((new Address(address)).toUint().getValue().toByteArray());
    buffer.put(AttestationCrypto.hashWithKeccak(receiverIdentifier.getBytes(StandardCharsets.UTF_8)));
    buffer.put(AttestationCrypto.hashWithKeccak(otherData));
    return buffer.array();
  }

  public static boolean validateNonce(byte[] nonce, String senderIdentifier, String address, String receiverIdentifier) {
    return validateNonce(nonce, senderIdentifier, address, receiverIdentifier, new byte[0]);
  }

  public static boolean validateNonce(byte[] nonce, String senderIdentifier,
      String address, String receiverIdentifier, byte[] otherData) {
    long currentTime = Clock.systemUTC().millis();
    if (!validateTimestamp(getTimestamp(nonce), currentTime)) {
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
        Long.BYTES + AttestationCrypto.BYTES_IN_DIGEST + (Address.DEFAULT_LENGTH/8));
    Address addressObject = new Address(address);
    byte[] recomputedKeyDigest = addressObject.toUint().getValue().toByteArray();
    return Arrays.equals(referenceAddress, recomputedKeyDigest);
  }

  static boolean validateReceiverIdentifier(byte[] nonce, String receiverIdentifier) {
    byte[] receiverIdentifierDigest = Arrays.copyOfRange(nonce,
        Long.BYTES + AttestationCrypto.BYTES_IN_DIGEST + (Address.DEFAULT_LENGTH/8),
        Long.BYTES + 2 * AttestationCrypto.BYTES_IN_DIGEST + (Address.DEFAULT_LENGTH/8));
    byte[] recomputedReceiverIdentifierDigest = AttestationCrypto.hashWithKeccak(
        receiverIdentifier.getBytes(StandardCharsets.UTF_8));
    return Arrays.equals(receiverIdentifierDigest, recomputedReceiverIdentifierDigest);
  }

  static boolean validateOtherData(byte[] nonce, byte[] otherData) {
    byte[] receiverOtherData = Arrays.copyOfRange(nonce,
        Long.BYTES + 2 * AttestationCrypto.BYTES_IN_DIGEST + (Address.DEFAULT_LENGTH/8),
        Long.BYTES + 3 * AttestationCrypto.BYTES_IN_DIGEST + (Address.DEFAULT_LENGTH/8));
    byte[] recomputedReceiverOtherData = AttestationCrypto.hashWithKeccak(otherData);
    return Arrays.equals(receiverOtherData, recomputedReceiverOtherData);
  }

  static long getTimestamp(byte[] nonce) {
    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
    buffer.put(Arrays.copyOfRange(nonce, 0, Long.BYTES));
    buffer.flip();
    return buffer.getLong();
  }

  static boolean validateTimestamp(long timestamp, long currentTime) {
    if (timestamp > currentTime + TIMESTAMP_SLACK_MS) {
      return false;
    }
    if (timestamp < currentTime - TIMESTAMP_SLACK_MS) {
      return false;
    }
    return true;
  }
}
