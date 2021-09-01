package org.tokenscript.attestation;

import org.tokenscript.attestation.core.Attestable;
import java.io.IOException;

public interface AttestableObjectDecoder<T extends Attestable> {
  public T decode(byte[] encoding) throws IOException;
}
