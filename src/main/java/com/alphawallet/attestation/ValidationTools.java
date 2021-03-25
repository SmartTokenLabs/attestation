package com.alphawallet.attestation;

import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;

public class ValidationTools {
  // Characters in the string representation of an address
  public static final int ADDRESS_LENGTH_IN_BYTES = 42;

  public static boolean validateTimestampWSlack(long timestamp, long currentTime, long timestampSlack) {
    if (timestamp > currentTime + timestampSlack) {
      return false;
    }
    if (timestamp < currentTime - timestampSlack) {
      return false;
    }
    return true;
  }


  public static boolean isAddress(String address) {
    if (address.length() != ADDRESS_LENGTH_IN_BYTES) {
      return false;
    }
    if (!address.substring(0, 2).equals("0x")) {
      return false;
    }
    try {
      Hex.decodeStrict(address.substring(2));
    } catch (DecoderException e) {
      return false;
    }
    return true;
  }

  public static boolean isNullOrAddress(String address) {
    if (address == null) {
      return true;
    }
    return isAddress(address);
  }
}
