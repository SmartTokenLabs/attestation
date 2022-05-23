package org.tokenscript.attestation;

import org.tokenscript.attestation.core.ASNEncodable;
import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

public interface ProofOfExponent extends ASNEncodable {
  public ECPoint getPoint();
  public BigInteger getChallengeResponse();
  public byte[] getUnpredictableNumber();
  // Verify that the parameters are safe, without validating the proof itself
  public boolean validateParameters();
}
