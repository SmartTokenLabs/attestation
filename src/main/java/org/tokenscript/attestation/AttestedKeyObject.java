package org.tokenscript.attestation;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public abstract class AttestedKeyObject implements CheckableObject {
  public abstract AsymmetricKeyParameter getAttestedUserKey();
}
