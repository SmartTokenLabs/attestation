package org.tokenscript.attestation;

import org.tokenscript.attestation.core.ASNEncodable;
import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

public interface ProofOfExponent extends ASNEncodable {
  public ECPoint getPoint();
  public BigInteger getChallenge();
  public byte[] getNonce();
}
