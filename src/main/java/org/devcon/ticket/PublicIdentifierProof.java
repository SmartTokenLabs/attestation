package org.devcon.ticket;

import java.io.InvalidObjectException;
import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.math.ec.ECPoint;
import org.tokenscript.attestation.FullProofOfExponent;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.core.ASNEncodable;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.Verifiable;

public class PublicIdentifierProof implements ASNEncodable, Verifiable {
  private final AttestationCrypto crypto;
  private final byte[] referenceCommitment;
  private final String identifier;
  private final AttestationType type;
  private final FullProofOfExponent pok;

  public PublicIdentifierProof(AttestationCrypto crypto, byte[] commitment, String identifier, AttestationType type, BigInteger secret) {
    this.crypto = crypto;
    this.referenceCommitment = commitment;
    this.identifier = identifier;
    this.type = type;
    this.pok = crypto.computeAttestationProof(secret);
  }

  public PublicIdentifierProof(AttestationCrypto crypto, byte[] commitment, String identifier, AttestationType type, FullProofOfExponent pok) {
    this.crypto = crypto;
    this.referenceCommitment = commitment;
    this.identifier = identifier;
    this.type = type;
    this.pok = pok;
  }

  public FullProofOfExponent getPok()  {
    return pok;
  }

  @Override
  public boolean verify() {
    if (!verifyCommitment()) {
      return false;
    }
    if (!crypto.verifyFullProof(pok)) {
      return false;
    }
    return true;
  }

  private boolean verifyCommitment() {
    BigInteger hashedIdentifier = crypto.mapToCurveMultiplier(type, identifier);
    ECPoint hiddenMessagePoint = crypto.G.multiply(hashedIdentifier);
    byte[] expectedCommitment = pok.getRiddle().add(hiddenMessagePoint).getEncoded(false);
    if (!Arrays.equals(expectedCommitment, referenceCommitment)) {
      return false;
    }
    return true;
  }

  @Override
  public byte[] getDerEncoding() throws InvalidObjectException {
    return pok.getDerEncoding();
  }
}
