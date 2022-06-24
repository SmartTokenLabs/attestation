package org.tokenscript.attestation.safeconnect;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.tokenscript.attestation.CheckableObject;
import org.tokenscript.attestation.SignedIdentifierAttestation;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.SignatureUtility;

import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Clock;
import java.util.Date;

public abstract class AbstractSignedOwnershipAttestation implements CheckableObject {
    // tODO move to signature utility and change to pkcs1 1.5
    public static final AlgorithmIdentifier RSASSA_PSS_ALG = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.10"));
    private static final Logger logger = LogManager.getLogger(AbstractSignedOwnershipAttestation.class);

    // TODO use timestamp
    protected static Date getCurrentTime() {
        long tempTime = Clock.systemUTC().millis();
        // Round down to ensure consistent encoding and decoding
        return new Date(tempTime - (tempTime % 1000));
    }

    // TODO move to signature utility
    protected static AlgorithmIdentifier getSigningAlgorithm(AsymmetricKeyParameter signingKey) {
        if (signingKey instanceof ECKeyParameters) {
            return SignedIdentifierAttestation.ECDSA_WITH_SHA256;
        } else if (signingKey instanceof RSAKeyParameters) {
            return RSASSA_PSS_ALG;
        } else {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Only ECDSA or RSA keys are supported"));
        }
    }

    abstract protected byte[] getUnsignedEncoding();

    abstract protected byte[] getSignature();

    abstract protected Date getNotBefore();

    abstract protected Date getNotAfter();

    abstract protected AsymmetricKeyParameter getVerificationKey();

    protected byte[] makeSignature(byte[] unsignedEncoding, AsymmetricCipherKeyPair signingKey) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            if (getSigningAlgorithm(signingKey.getPrivate()).equals(SignedIdentifierAttestation.ECDSA_WITH_SHA256)) {
                // To be compatible with SubtleCrypto we can only use NIST curves, so we go with P-256 i.e secp256r1
                Signature ecdsaSig = Signature.getInstance("SHA256withECDSA", "BC");
                ecdsaSig.initSign(
                        SignatureUtility.convertPrivateBouncyCastleKeyToJavaKey(signingKey.getPrivate()));
                ecdsaSig.update(unsignedEncoding);
                return ecdsaSig.sign();
//            // We assume that signing will be done with the Ethereum paradigm as for signed attestations
//            return SignatureUtility.signWithEthereum(unsignedEncoding, signingKey.getPrivate());
            }
            if (getSigningAlgorithm(signingKey.getPrivate()).equals(RSASSA_PSS_ALG)) {
                // See https://stackoverflow.com/questions/53728536/how-to-sign-with-rsassa-pss-in-java-correctly
                // for details on this and how to verify using openssl
                Signature signatureSHA256Java = Signature.getInstance("SHA256withRSA/PSS", "BC");
                signatureSHA256Java.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                signatureSHA256Java.initSign(
                        SignatureUtility.convertPrivateBouncyCastleKeyToJavaKey(signingKey.getPrivate()));
                signatureSHA256Java.update(unsignedEncoding);
                return signatureSHA256Java.sign();
            }
        } catch (Exception e) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Could not perform signing"));
        }
        throw ExceptionUtil.throwException(logger,
                new IllegalArgumentException("Only ECDSA or RSA keys are supported"));
    }

    protected byte[] makeSignedEncoding(byte[] unsignedEncoding, byte[] signature, AsymmetricKeyParameter key) {
        try {
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(ASN1Primitive.fromByteArray(unsignedEncoding));
            res.add(getSigningAlgorithm(key));
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

    @Override
    public boolean verify() {
        try {
            if (getSigningAlgorithm(getVerificationKey()).equals(SignedIdentifierAttestation.ECDSA_WITH_SHA256)) {
                // To be compatible with SubtleCrypto we can only use NIST curves, so we go with P-256 i.e secp256r1
                Signature ecdsaSig = Signature.getInstance("SHA256withECDSA", "BC");
                ecdsaSig.initVerify(
                        SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(getVerificationKey()));
                ecdsaSig.update(getUnsignedEncoding());
                return ecdsaSig.verify(getSignature());
//            if (!SignatureUtility.verifyEthereumSignature(unsignedEncoding, signature, getVerificationKey())) {
//                logger.error("Signature is not valid");
//                return false;
//            }
            }
            if (getSigningAlgorithm(getVerificationKey()).equals(RSASSA_PSS_ALG)) {
                // TODO refactor into SignatureUtility
                // See https://stackoverflow.com/questions/53728536/how-to-sign-with-rsassa-pss-in-java-correctly
                // for details on this and how to verify using openssl
                Signature signatureSHA256Java = Signature.getInstance("SHA256withRSA/PSS", "BC");
                signatureSHA256Java.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                signatureSHA256Java.initVerify(
                        SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(getVerificationKey()));
                signatureSHA256Java.update(getUnsignedEncoding());
                return signatureSHA256Java.verify(getSignature());
            }
        } catch (Exception e) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Could not perform verification"));
        }
        logger.error("Unknown key format");
        return false;
    }
}
