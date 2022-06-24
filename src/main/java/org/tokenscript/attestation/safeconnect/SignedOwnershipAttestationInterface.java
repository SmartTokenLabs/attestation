package org.tokenscript.attestation.safeconnect;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.CheckableObject;

import java.util.Date;

public interface SignedOwnershipAttestationInterface extends CheckableObject {
    byte[] getContext();

    AsymmetricKeyParameter getSubjectPublicKey();

    Date getNotBefore();

    Date getNotAfter();

    AsymmetricKeyParameter getVerificationKey();
}
