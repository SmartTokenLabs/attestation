package org.tokenscript.attestation.safeconnect;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.core.ExceptionUtil;

import java.util.Date;

public class SignedEthereumAddressAttestation extends AbstractSignedOwnershipAttestation implements SignedOwnershipAttestationInterface {
    public static final long DEFAULT_VALIDITY = 60 * 60 * 24; // 1 day
    private static final Logger logger = LogManager.getLogger(SignedEthereumAddressAttestation.class);
    private final EthereumAddressAttestation internalAtt;
    private final AsymmetricKeyParameter verificationKey;
    private final byte[] unsignedEncoding;
    private final byte[] signature;
    private final byte[] signedEncoding;

    public SignedEthereumAddressAttestation(byte[] context, AsymmetricKeyParameter subjectPublicKey, String subjectAddress, long validityInSeconds, AsymmetricCipherKeyPair signingKey) {
        if (validityInSeconds < 0) {
            throw new IllegalArgumentException("NotBefore or NotAfter time is negative");
        }
        Date notBefore = getCurrentTime();
        Date notAfter = new Date(notBefore.getTime() + validityInSeconds * 1000);
        try {
            this.internalAtt = new EthereumAddressAttestation(context, subjectAddress, notBefore, notAfter, subjectPublicKey);
            this.verificationKey = signingKey.getPublic();
            this.unsignedEncoding = internalAtt.getDerEncoding();
            this.signature = makeSignature(unsignedEncoding, signingKey);
            this.signedEncoding = makeSignedEncoding(unsignedEncoding, signature, verificationKey);
        } catch (Exception e) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Could not parse arguments"));
        }
        constructorCheck();
    }

    public SignedEthereumAddressAttestation(byte[] context, AsymmetricKeyParameter subjectPublicKey, String subjectAddress, Date notBefore, Date notAfter, byte[] signature, AsymmetricKeyParameter verificationKey) {
        try {
            this.internalAtt = new EthereumAddressAttestation(context, subjectAddress, notBefore, notAfter, subjectPublicKey);
            this.verificationKey = verificationKey;
            this.unsignedEncoding = internalAtt.getDerEncoding();
            this.signature = signature;
            this.signedEncoding = makeSignedEncoding(unsignedEncoding, signature, verificationKey);
        } catch (Exception e) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Could not parse arguments"));
        }
        constructorCheck();
    }

    private void constructorCheck() {
        if (!verify()) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Signature is not valid"));
        }
    }

    @Override
    public byte[] getDerEncoding() {
        return signedEncoding;
    }

    @Override
    protected byte[] getUnsignedEncoding() {
        return unsignedEncoding;
    }

    @Override
    protected byte[] getSignature() {
        return signature;
    }

    @Override
    public boolean checkValidity() {
        if (!super.checkValidity()) {
            return false;
        }
        return internalAtt.checkValidity();
    }

    @Override
    public byte[] getContext() {
        return internalAtt.getContext();
    }

    @Override
    public AsymmetricKeyParameter getSubjectPublicKey() {
        return internalAtt.getSubjectPublicKey();
    }

    @Override
    public Date getNotBefore() {
        return internalAtt.getNotBefore();
    }

    @Override
    public Date getNotAfter() {
        return internalAtt.getNotAfter();
    }

    @Override
    public AsymmetricKeyParameter getVerificationKey() {
        return verificationKey;
    }

    public String getSubjectAddress() {
        return internalAtt.getSubjectAddress();
    }
}