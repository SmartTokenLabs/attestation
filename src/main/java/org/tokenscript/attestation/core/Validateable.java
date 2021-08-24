package org.tokenscript.attestation.core;

public interface Validateable {

  /**
   * Returns true of the user-defined, non-cryptographic data within the object is currently valid.
   */
  public boolean checkValidity();
}
