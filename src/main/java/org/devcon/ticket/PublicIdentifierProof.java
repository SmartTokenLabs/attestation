package org.devcon.ticket;

import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.math.ec.ECPoint;
import org.tokenscript.attestation.FullProofOfExponent;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.Verifiable;

public class PublicIdentifierProof implements Verifiable {
  private static final Logger logger = LogManager.getLogger(PublicIdentifierProof.class);

  private final byte[] referenceCommitment;
  private final String identifier;
  private final AttestationType type;
  private final FullProofOfExponent internalPok;

  public PublicIdentifierProof(AttestationCrypto crypto, byte[] commitment, String identifier, AttestationType type, BigInteger secret) {
    this.referenceCommitment = commitment;
    this.identifier = identifier;
    this.type = type;
    this.internalPok = crypto.computeAttestationProof(secret);
    constructorCheck();
  }

  public PublicIdentifierProof(byte[] commitment, String identifier,
      AttestationType type, FullProofOfExponent pok) {
    this.referenceCommitment = commitment;
    this.identifier = identifier;
    this.type = type;
    this.internalPok = pok;
    constructorCheck();
  }

  private void constructorCheck() {
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Proof, commitment and email not consistent or not valid"));
    }
  }
  public FullProofOfExponent getInternalPok()  {
    return internalPok;
  }

  @Override
  public boolean verify() {
    if (!verifyCommitment()) {
      return false;
    }
    if (!AttestationCrypto.verifyFullProof(internalPok)) {
      return false;
    }
    return true;
  }

  private boolean verifyCommitment() {
    BigInteger hashedIdentifier = AttestationCrypto.mapToCurveMultiplier(type, identifier);
    ECPoint hiddenMessagePoint = AttestationCrypto.G.multiply(hashedIdentifier);
    byte[] expectedCommitment = internalPok.getRiddle().add(hiddenMessagePoint).getEncoded(false);
    if (!Arrays.equals(expectedCommitment, referenceCommitment)) {
      return false;
    }
    return true;
  }

}
