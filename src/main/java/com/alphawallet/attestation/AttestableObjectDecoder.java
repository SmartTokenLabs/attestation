package com.alphawallet.attestation;

import com.alphawallet.attestation.core.Attestable;
import java.io.IOException;

public interface AttestableObjectDecoder<T extends Attestable> {
  public T decode(byte[] encoding) throws IOException;
}
