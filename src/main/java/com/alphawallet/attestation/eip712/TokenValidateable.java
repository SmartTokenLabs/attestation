package com.alphawallet.attestation.eip712;

public interface TokenValidateable {
  /**
   * Returns true if the longer-term token that the object represent is valid.
   */
  public boolean checkTokenValidity();
}
