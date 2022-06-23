package org.tokenscript.attestation.safeconnect;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.tokenscript.attestation.*;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.SignatureUtility;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Clock;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class SignedNFTOwnershipAttestation implements CheckableObject {

    // tODO move to signature utility
    public static final AlgorithmIdentifier RSASSA_PSS_ALG = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.10"));
//    public static final String GENERIC_ECDSA_OID = "1.2.840.10045.2.1";

    public static final long DEFAULT_VALIDITY = 60*60*24; // 1 day
    private static final Logger logger = LogManager.getLogger(SignedNFTOwnershipAttestation.class);
    private final byte[] context;
    private final AsymmetricKeyParameter subjectPublicKey;
    private final ERC721Token[] tokens;
    private final Date notBefore; // todo refactor to use timestamp class
    private final Date notAfter;

    private final AsymmetricKeyParameter verificationKey;
    private final byte[] unsignedEncoding;
    private final byte[] signature;
    private final byte[] signedEncoding;

    public SignedNFTOwnershipAttestation(byte[] context, AsymmetricKeyParameter subjectPublicKey, ERC721Token token, AsymmetricCipherKeyPair signingKey) {
        this(context, subjectPublicKey, token, DEFAULT_VALIDITY, signingKey);
    }

    public SignedNFTOwnershipAttestation(byte[] context, AsymmetricKeyParameter subjectPublicKey, ERC721Token token, long validityInSeconds, AsymmetricCipherKeyPair signingKey) {
        this(context, subjectPublicKey, new ERC721Token[] {token}, validityInSeconds, signingKey);
    }

    public SignedNFTOwnershipAttestation(byte[] context, AsymmetricKeyParameter subjectPublicKey, ERC721Token[] tokens, long validityInSeconds, AsymmetricCipherKeyPair signingKey) {
        try {
            if (validityInSeconds < 0) {
                throw new IllegalArgumentException("NotBefore or NotAfter time is negative");
            }
            this.notBefore = getCurrentTime();
            this.notAfter = new Date(this.notBefore.getTime() + validityInSeconds * 1000);
            this.context = context;
            this.subjectPublicKey = subjectPublicKey;
            this.tokens = tokens;
            this.verificationKey = signingKey.getPublic();
            this.unsignedEncoding = makeUnsignedEncoding();
            this.signature = makeSignature(unsignedEncoding, signingKey);
            this.signedEncoding = makeSignedEncoding(unsignedEncoding, signature, signingKey);
        } catch (Exception e) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Could not parse arguments"));
        }
    }

    public SignedNFTOwnershipAttestation(byte[] encoding, AsymmetricKeyParameter verificationKey) throws IOException {
        this.signedEncoding = encoding;
        this.verificationKey = verificationKey;
        ASN1InputStream input = null;
        try {
            input = new ASN1InputStream(encoding);
            ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
            ASN1Sequence ownershipAttEnc = ASN1Sequence.getInstance(asn1.getObjectAt(0));
            this.unsignedEncoding = ownershipAttEnc.getEncoded();

            int ownershipAttCtr = 0;
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(ownershipAttEnc.getObjectAt(ownershipAttCtr++));
            this.subjectPublicKey = PublicKeyFactory.createKey(subjectPublicKeyInfo);
            DERSequence tokensEnc = DERSequence.convert(
                    ASN1Sequence.getInstance(ownershipAttEnc.getObjectAt(ownershipAttCtr++)));
            this.tokens = new ERC721Token[tokensEnc.size()];
            for (int i = 0; i < tokensEnc.size(); i++) {
                tokens[i] = new ERC721Token(tokensEnc.getObjectAt(i).toASN1Primitive().getEncoded());
            }
            ASN1Sequence validity = DERSequence.convert(
                    ASN1Sequence.getInstance(ownershipAttEnc.getObjectAt(ownershipAttCtr++)));
            ASN1Integer notBeforeEnc = ASN1Integer.getInstance(validity.getObjectAt(0));
            // Multiply with 1000 since the data is stored in seconds and not milliseconds
            this.notBefore = new Date( notBeforeEnc.longValueExact() * 1000);
            ASN1Integer notAfterEnc = ASN1Integer.getInstance(validity.getObjectAt(1));
            this.notAfter = new Date(notAfterEnc.longValueExact() * 1000);
            byte[] decodedContext;
            try {
                decodedContext = ASN1OctetString.getInstance(ownershipAttEnc.getObjectAt(ownershipAttCtr)).getOctets();
                ownershipAttCtr++;
            } catch (Exception e) {
                // Context is not included
                decodedContext = null;
            }
            this.context = decodedContext;

            AlgorithmIdentifier algorithmEncoded = AlgorithmIdentifier.getInstance(asn1.getObjectAt(1));
            ASN1BitString signatureEnc = ASN1BitString.getInstance(asn1.getObjectAt(2));
            this.signature = signatureEnc.getBytes();

            if (!algorithmEncoded.equals(getSigningAlgorithm(verificationKey))) {
                throw ExceptionUtil.throwException(logger,
                        new IllegalArgumentException("Algorithm specified is does not work with verification key supplied"));
            }
            constructorCheck();
        } finally {
            input.close();
        }
    }

    private void constructorCheck() {
        if (!verify()) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Signature is not valid"));
        }
    }

    // TODO use timestamp
    private static Date getCurrentTime() {
        long tempTime = Clock.systemUTC().millis();
        // Round down to ensure consistent encoding and decoding
        return new Date(tempTime - (tempTime % 1000));
    }

    private byte[] makeUnsignedEncoding() {
        try {
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(getSubjectPublicKey()));
            ASN1EncodableVector asn1Tokens = new ASN1EncodableVector();
            for (ERC721Token token : getTokens())
            {
                asn1Tokens.add(ASN1Sequence.getInstance(token.getDerEncoding()));
            }
            res.add(new DERSequence(asn1Tokens));
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

    private byte[] makeSignedEncoding(byte[] unsignedEncoding, byte[] signature, AsymmetricCipherKeyPair signingKey) {
        try {
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(ASN1Primitive.fromByteArray(unsignedEncoding));
            res.add(getSigningAlgorithm(signingKey.getPrivate()));
            res.add(new DERBitString(signature));
            return new DERSequence(res).getEncoded();
        } catch (Exception e) {
            throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
        }
    }

    // TODO move to signature utility
    private AlgorithmIdentifier getSigningAlgorithm(AsymmetricKeyParameter signingKey) {
        if (signingKey instanceof ECKeyParameters) {
            return SignedIdentifierAttestation.ECDSA_WITH_SHA256;
        } else if (signingKey instanceof RSAKeyParameters) {
            return RSASSA_PSS_ALG;
        } else {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Only ECDSA or RSA keys are supported"));
        }
    }

    private byte[] makeSignature(byte[] unsignedEncoding, AsymmetricCipherKeyPair signingKey) {
        if (getSigningAlgorithm(signingKey.getPrivate()).equals(SignedIdentifierAttestation.ECDSA_WITH_SHA256)) {
            // We assume that signing will be done with the Ethereuem paradigm as for signed attestations
            return SignatureUtility.signWithEthereum(unsignedEncoding, signingKey.getPrivate());
        } else if (getSigningAlgorithm(signingKey.getPrivate()).equals(RSASSA_PSS_ALG)) {
            // See https://stackoverflow.com/questions/53728536/how-to-sign-with-rsassa-pss-in-java-correctly
            // for details on this and how to verify using openssl
            try {
                Signature signatureSHA256Java = Signature.getInstance("SHA256withRSA/PSS");
                signatureSHA256Java.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                signatureSHA256Java.initSign(
                        SignatureUtility.convertPrivateBouncyCastleKeyToJavaKey(signingKey.getPrivate()));
                signatureSHA256Java.update(unsignedEncoding);
                return signatureSHA256Java.sign();
            } catch (Exception e) {
                throw ExceptionUtil.throwException(logger,
                        new IllegalArgumentException("Could not perform RSA signing"));
            }
        } else {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Only ECDSA or RSA keys are supported"));
        }
    }

    public byte[] getContext() {
        return context;
    }

    public AsymmetricKeyParameter getSubjectPublicKey() {
        return subjectPublicKey;
    }

    public ERC721Token[] getTokens() {
        return tokens;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public AsymmetricKeyParameter getVerificationKey() {
        return verificationKey;
    }

    @Override
    public byte[] getDerEncoding() throws InvalidObjectException {
        return signedEncoding;
    }

    @Override
    public boolean checkValidity() {
        Date currentTime = getCurrentTime();
        if (currentTime.compareTo(getNotBefore()) < 0) {
            // Current time is before notBefore
            return false;
        }
        if (currentTime.compareTo(getNotAfter()) > 0) {
            // Current time is after notAfter
            return false;
        }
        for (ERC721Token current : getTokens()) {
            if (!current.checkValidity()) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean verify() {
        if (getSigningAlgorithm(getVerificationKey()).equals(SignedIdentifierAttestation.ECDSA_WITH_SHA256)) {
            if (!SignatureUtility.verifyEthereumSignature(unsignedEncoding, signature, getVerificationKey())) {
                logger.error("Signature is not valid");
                return false;
            }
        } else if (getSigningAlgorithm(getVerificationKey()).equals(RSASSA_PSS_ALG)) {
            // TODO refactor into SignatureUtility
            // See https://stackoverflow.com/questions/53728536/how-to-sign-with-rsassa-pss-in-java-correctly
            // for details on this and how to verify using openssl
            try {
                Signature signatureSHA256Java = Signature.getInstance("SHA256withRSA/PSS");
                signatureSHA256Java.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                signatureSHA256Java.initVerify(
                        SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(getVerificationKey()));
                signatureSHA256Java.update(unsignedEncoding);
                if (!signatureSHA256Java.verify(signature)) {
                    logger.error("Signature is not valid");
                    return false;
                }
            } catch (Exception e) {
                throw ExceptionUtil.throwException(logger,
                        new IllegalArgumentException("Could not perform RSA verification"));
            }
        } else {
            logger.error("Unknown key format");
            return false;
        }
        return true;
    }
}
