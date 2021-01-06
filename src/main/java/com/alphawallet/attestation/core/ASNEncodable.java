package com.alphawallet.attestation.core;

import java.io.InvalidObjectException;

public interface ASNEncodable {

  /**
   * Returns the _minimal_ DER encoding of the object.
   * That is, all optional fields are _excluded_!
   */
  public byte[] getDerEncoding() throws InvalidObjectException;
}
