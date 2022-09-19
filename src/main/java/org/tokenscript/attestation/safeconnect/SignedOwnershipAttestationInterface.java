package org.tokenscript.attestation.safeconnect;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface SignedOwnershipAttestationInterface extends OwnershipAttestationInterface {
    AsymmetricKeyParameter getVerificationKey();
}
