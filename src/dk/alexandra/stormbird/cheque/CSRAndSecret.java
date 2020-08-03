package dk.alexandra.stormbird.cheque;

import dk.alexandra.stormbird.cheque.asnobjects.Proof;
import java.math.BigInteger;
import org.bouncycastle.jce.PKCS10CertificationRequest;

public class CSRAndSecret {
  private final PKCS10CertificationRequest csr;
  private final BigInteger secret;
  private final Proof proof;
  private final byte[] proofSignature;

  public CSRAndSecret(PKCS10CertificationRequest csr, BigInteger secret, Proof proof, byte[] proofSignature) {
    this.csr = csr;
    this.secret = secret;
    this.proof = proof;
    this.proofSignature = proofSignature;
  }

  public PKCS10CertificationRequest getCsr() {
    return csr;
  }

  public BigInteger getSecret() {
    return secret;
  }

  public Proof getProof() { return proof; }

  public byte[] getProofSignature() { return proofSignature; }
}
