package org.tokenscript.attestation.safeconnect;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.CheckableObject;

import java.util.Date;

public interface OwnershipAttestationInterface extends CheckableObject {
    byte[] getContext();

    AsymmetricKeyParameter getSubjectPublicKey();

    Date getNotBefore();

    Date getNotAfter();

    /**
     * Returns the tag number for the underlying attestation element
     */
    int getTag();
}
