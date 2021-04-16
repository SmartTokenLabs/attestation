package com.alphawallet.attestation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;

public class ValidationTools {
  private static final Logger logger = LogManager.getLogger(ValidationTools.class);
  // Characters in the string representation of an address
  public static final int ADDRESS_LENGTH_IN_BYTES = 42;


  public static boolean isAddress(String address) {
    if (address.length() != ADDRESS_LENGTH_IN_BYTES) {
      logger.error("Address has wrong length");
      return false;
    }
    if (!address.substring(0, 2).toUpperCase().equals("0X")) {
      logger.error("Address does not have \"0x\" prefix");
      return false;
    }
    try {
      Hex.decodeStrict(address.substring(2));
    } catch (DecoderException e) {
      logger.error("Address is not a hex string");
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
