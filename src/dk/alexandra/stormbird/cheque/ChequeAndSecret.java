package dk.alexandra.stormbird.cheque;

import java.math.BigInteger;

public class ChequeAndSecret {
  private final SignedCheque cheque;
  private final BigInteger secret;

  public ChequeAndSecret(SignedCheque cheque, BigInteger secret) {
    this.cheque = cheque;
    this.secret = secret;
  }

  public SignedCheque getCheque() {
    return cheque;
  }

  public BigInteger getSecret() {
    return secret;
  }

}
