package org.tokenscript.attestation.safeconnect;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.SignatureUtility;
import org.web3j.utils.Numeric;

import java.io.InvalidObjectException;
import java.util.Date;

public class SignedEthereumKeyLinkingAttestation extends AbstractSignedOwnershipAttestation {
    public static final long DEFAULT_VALIDITY = 60 * 60; // 1 hour
    private static final Logger logger = LogManager.getLogger(SignedEthereumKeyLinkingAttestation.class);
    private final String subjectAddress;
    private final byte[] context;
    private final SignedOwnershipAttestationInterface ownershipAttestation;
    private final AsymmetricKeyParameter verificationKey;
    private final Date notBefore;
    private final Date notAfter;
    private final byte[] unsignedEncoding;
    private final byte[] signature;
    private final byte[] signedEncoding;

    public SignedEthereumKeyLinkingAttestation(byte[] context, String subjectAddress, SignedOwnershipAttestationInterface ownershipAttestation, AsymmetricCipherKeyPair signingKey) {
        this(context, subjectAddress, DEFAULT_VALIDITY, ownershipAttestation, signingKey);
    }

    public SignedEthereumKeyLinkingAttestation(byte[] context, String subjectAddress, long validityInSeconds, SignedOwnershipAttestationInterface ownershipAttestation, AsymmetricCipherKeyPair signingKey) {
        if (validityInSeconds < 0) {
            throw new IllegalArgumentException("NotBefore or NotAfter time is negative");
        }
        this.notBefore = getCurrentTime();
        this.notAfter = new Date(this.notBefore.getTime() + validityInSeconds * 1000);
        try {
            this.context = context;
            this.subjectAddress = subjectAddress;
            this.ownershipAttestation = ownershipAttestation;
            // The attestation has to be signed with the key attested to
            this.verificationKey = ownershipAttestation.getSubjectPublicKey();
            this.unsignedEncoding = makeUnsignedEncoding();
            this.signature = SignatureUtility.signWithStandardScheme(unsignedEncoding, signingKey);
            this.signedEncoding = makeSignedEncoding(unsignedEncoding, signature, verificationKey);
        } catch (Exception e) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Could not parse arguments"));
        }
        constructorCheck();
    }

    public SignedEthereumKeyLinkingAttestation(byte[] context, String subjectAddress, Date notBefore, Date notAfter, SignedOwnershipAttestationInterface ownershipAttestation, byte[] signature) {
        try {
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.context = context;
            this.subjectAddress = subjectAddress;
            this.ownershipAttestation = ownershipAttestation;
            // The attestation has to be signed with the key attested to
            this.verificationKey = ownershipAttestation.getSubjectPublicKey();
            this.unsignedEncoding = makeUnsignedEncoding();
            this.signature = signature;
            this.signedEncoding = makeSignedEncoding(unsignedEncoding, this.signature, verificationKey);
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

    protected byte[] makeUnsignedEncoding() {
        try {
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(new DEROctetString(Numeric.hexStringToByteArray(getSubjectAddress())));
            res.add(ASN1Primitive.fromByteArray(getOwnershipAttestation().getDerEncoding()));
            ASN1EncodableVector validity = new ASN1EncodableVector();
            validity.add(new ASN1Integer(getNotBefore().toInstant().getEpochSecond()));
            validity.add(new ASN1Integer(getNotAfter().toInstant().getEpochSecond()));
            res.add(new DERSequence(validity));
            if (getContext() != null) {
                res.add(new DEROctetString(getContext()));
            }
            return new DERSequence(res).getEncoded();
        } catch (Exception e) {
            throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
        }
    }

    public String getSubjectAddress() {
        return subjectAddress;
    }

    public byte[] getContext() {
        return context;
    }

    public SignedOwnershipAttestationInterface getOwnershipAttestation() {
        return ownershipAttestation;
    }

    @Override
    public Date getNotBefore() {
        return notBefore;
    }

    @Override
    public Date getNotAfter() {
        return notAfter;
    }

    @Override
    public AsymmetricKeyParameter getVerificationKey() {
        return getOwnershipAttestation().getSubjectPublicKey();
    }

    @Override
    public byte[] getDerEncoding() throws InvalidObjectException {
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
        return ownershipAttestation.checkValidity();
    }

    @Override
    public boolean verify() {
        if (!SignatureUtility.verifyWithStandardScheme(getUnsignedEncoding(), getSignature(), getVerificationKey())) {
            return false;
        }
        return ownershipAttestation.verify();
    }
}
