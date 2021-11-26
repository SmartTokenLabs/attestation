package org.tokenscript.attestation;

import java.io.IOException;

public interface ObjectDecoder<T extends CheckableObject> {
  public T decode(byte[] encoding) throws IOException;
}
