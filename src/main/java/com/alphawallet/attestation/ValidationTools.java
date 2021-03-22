package com.alphawallet.attestation;

import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;

public class ValidationTools {

  public static boolean validateTimestamp(long timestamp, long currentTime, long timestampSlack) {
    if (timestamp > currentTime + timestampSlack) {
      return false;
    }
    if (timestamp < currentTime - timestampSlack) {
      return false;
    }
    return true;
  }

  public static boolean isAddress(String address) {
    if (address.length() != 42) {
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
