package org.tokenscript.attestation;

import org.tokenscript.attestation.core.ASNEncodable;
import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;
import org.tokenscript.attestation.core.Verifiable;

public interface ProofOfExponent extends ASNEncodable, Verifiable {
  public ECPoint getPoint();
  public BigInteger getChallenge();
  public byte[] getUnpredictableNumber();
}
