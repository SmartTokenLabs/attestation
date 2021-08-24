package org.tokenscript.attestation.core;

public interface Attestable extends ASNEncodable, Verifiable, Validateable {
  public byte[] getCommitment();
}
