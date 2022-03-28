package org.tokenscript.attestation.core;

import org.tokenscript.attestation.CheckableObject;

public abstract class Attestable implements CheckableObject {
  public abstract byte[] getCommitment();
}
