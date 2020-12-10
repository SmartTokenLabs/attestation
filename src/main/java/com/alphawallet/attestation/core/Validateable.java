package com.alphawallet.attestation.core;

public interface Validateable {

  /**
   * Returns true of the user-defined, non-cryptographic data within the object is valid.
   */
  public boolean checkValidity();
}
