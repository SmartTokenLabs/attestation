package org.tokenscript.attestation;

import java.io.IOException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.core.Attestable;

public class AttestedObjectDecoder<UnderlyingT extends Attestable> implements ObjectDecoder<AttestedObject<UnderlyingT>> {
  private ObjectDecoder underlyingDecoder;
  private AsymmetricKeyParameter publicAttestationSigningKey;

  public AttestedObjectDecoder(ObjectDecoder underlyingObjectDecoder, AsymmetricKeyParameter publicAttestationSigningKey) {
    this.underlyingDecoder = underlyingObjectDecoder;
    this.publicAttestationSigningKey = publicAttestationSigningKey;
  }

  @Override
  public AttestedObject decode(byte[] encoding) throws IOException {
    return new AttestedObject(encoding, underlyingDecoder, publicAttestationSigningKey);
  }
}
