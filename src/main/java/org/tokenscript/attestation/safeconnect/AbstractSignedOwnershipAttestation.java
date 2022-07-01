package org.tokenscript.attestation.safeconnect;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.CheckableObject;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.SignatureUtility;

import java.time.Clock;
import java.util.Date;

public abstract class AbstractSignedOwnershipAttestation implements CheckableObject {

    private static final Logger logger = LogManager.getLogger(AbstractSignedOwnershipAttestation.class);

    protected Date getCurrentTime() {
        long tempTime = Clock.systemUTC().millis();
        // Round down to ensure consistent encoding and decoding
        return new Date(tempTime - (tempTime % 1000));
    }

    abstract protected byte[] getUnsignedEncoding();

    abstract protected byte[] getSignature();

    abstract protected Date getNotBefore();

    abstract protected Date getNotAfter();

    abstract protected AsymmetricKeyParameter getVerificationKey();

    protected byte[] makeSignedEncoding(byte[] unsignedEncoding, byte[] signature, AsymmetricKeyParameter key) {
        try {
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(ASN1Primitive.fromByteArray(unsignedEncoding));
            res.add(SignatureUtility.getSigningAlgorithm(key));
            res.add(new DERBitString(signature));
            return new DERSequence(res).getEncoded();
        } catch (Exception e) {
            throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
        }
    }

    @Override
    public boolean checkValidity() {
        Date currentTime = getCurrentTime();
        if (currentTime.compareTo(getNotBefore()) < 0) {
            // Current time is before notBefore
            return false;
        }
        // Current time is after notAfter
        return currentTime.compareTo(getNotAfter()) <= 0;
    }

}
