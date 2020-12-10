package com.alphawallet.attestation;

import java.io.InvalidObjectException;

public interface ASNEncodable {
  public byte[] getDerEncoding() throws InvalidObjectException;
}
