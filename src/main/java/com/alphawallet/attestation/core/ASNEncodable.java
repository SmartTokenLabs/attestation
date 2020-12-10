package com.alphawallet.attestation.core;

import java.io.InvalidObjectException;

public interface ASNEncodable {
  public byte[] getDerEncoding() throws InvalidObjectException;
}
