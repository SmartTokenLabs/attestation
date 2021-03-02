package com.alphawallet.attestation;

import com.alphawallet.attestation.core.ASNEncodable;
import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

public interface ProofOfExponent extends ASNEncodable {
  public ECPoint getPoint();
  public BigInteger getChallenge();
  public byte[] getNonce();
}
