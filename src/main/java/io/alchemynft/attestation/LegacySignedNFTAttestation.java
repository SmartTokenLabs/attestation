package io.alchemynft.attestation;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.core.CompressedMsgSignature;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.PersonalSignature;
import org.tokenscript.attestation.core.Signature;

public class LegacySignedNFTAttestation implements InternalSignedNFTAttestation {
    private static final Logger logger = LogManager.getLogger(LegacySignedNFTAttestation.class);
    public static final int DEFAULT_SIGNING_VERSION = 2;

    private final NFTAttestation nftAtt;
    private final Signature signature;
    private final int signingVersion;

    public LegacySignedNFTAttestation(NFTAttestation nftAtt, AsymmetricKeyParameter subjectSigningKey) {
        this(nftAtt, subjectSigningKey, DEFAULT_SIGNING_VERSION);
    }

    public LegacySignedNFTAttestation(NFTAttestation nftAtt, AsymmetricKeyParameter subjectSigningKey, int signingVersion) {
        this.nftAtt = nftAtt;
        this.signature = makeSignature(subjectSigningKey, signingVersion);
        this.signingVersion = signingVersion;

        if (!verify()) {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("The signature is not valid"));
        }
    }

    /**
     * Constructor used for when we supply the signature separately
     */
    public LegacySignedNFTAttestation(NFTAttestation NftAtt, Signature signature) {
        this.nftAtt = NftAtt;
        this.signature = signature;
        this.signingVersion = determineSigningVersion();
        if (!verify()) {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("The signature is not valid"));
        }
    }

    public LegacySignedNFTAttestation(byte[] derEncoding, AsymmetricKeyParameter identifierAttestationVerificationKey) throws IOException {
        ASN1InputStream input = null;
        try {
            input = new ASN1InputStream(derEncoding);
            ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
            input.close();
            int currentPos = 0;
            ASN1Sequence nftEncoding = ASN1Sequence.getInstance(asn1.getObjectAt(currentPos++));
            this.nftAtt = new NFTAttestation(nftEncoding.getEncoded(), identifierAttestationVerificationKey);
            if (asn1.getObjectAt(currentPos) instanceof ASN1Integer) {
                this.signingVersion = ASN1Integer.getInstance(asn1.getObjectAt(currentPos++)).intValueExact();
            } else {
                // If signingVersion is not present we default to version 1
                this.signingVersion = 1;
            }
            // todo this actually not used
            AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(asn1.getObjectAt(currentPos++));
            DERBitString signatureEnc = DERBitString.getInstance(asn1.getObjectAt(currentPos++));
            this.signature = makeSignature(signatureEnc.getBytes(), signingVersion);
        } finally {
            input.close();
        }
    }

    private int determineSigningVersion() {
        if (signature instanceof PersonalSignature) {
            return 1;
        }
        else if (signature instanceof CompressedMsgSignature) {
            return 2;
        } else {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Unexpected signature type used"));
        }
    }

    Signature makeSignature(byte[] encodedBytes, int signingVersion) {
        if (signingVersion == 1) {
            return new PersonalSignature(encodedBytes);
        }
        else if (signingVersion == 2) {
            return new CompressedMsgSignature(encodedBytes, SignedNFTAttestation.PREFIX_MSG, SignedNFTAttestation.POSTFIX_MSG);
        } else {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Unknown signing version"));
        }
    }

    Signature makeSignature(AsymmetricKeyParameter key, int signingVersion) {
        if (signingVersion == 1) {
            return new PersonalSignature(key, nftAtt.getDerEncoding());
        }
        else if (signingVersion == 2) {
            return new CompressedMsgSignature(key, nftAtt.getDerEncoding(), SignedNFTAttestation.PREFIX_MSG, SignedNFTAttestation.POSTFIX_MSG);
        } else {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Unknown signing version"));
        }
    }

    @Override
    public NFTAttestation getUnsignedAttestation() {
        return nftAtt;
    }

    @Override
    public byte[] getRawSignature() {
        return signature.getRawSignature();
    }

    public Signature getSignature() {
        return signature;
    }

    /**
     * Returns the public key of the NFTattestation signer
     */
    @Override
    public AsymmetricKeyParameter getNFTAttestationVerificationKey() {
        return nftAtt.getAttestedUserKey();
    }

    @Override
    public byte[] getDerEncoding() {
        return constructSignedAttestation(this.nftAtt,  this.signature.getRawSignature());
    }

    byte[] constructSignedAttestation(NFTAttestation unsignedAtt, byte[] signature) {
        try {
            byte[] rawAtt = unsignedAtt.getDerEncoding();
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(ASN1Primitive.fromByteArray(rawAtt));
            //  Only include version number if it is greater than 1
            if (signingVersion > 1) {
                res.add(new ASN1Integer(signingVersion));
            }
            res.add(unsignedAtt.getSigningAlgorithm());
            res.add(new DERBitString(signature));
            return new DERSequence(res).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int getSigningVersion() {
        return signingVersion;
    }

    @Override
    public boolean checkValidity() {
        return getUnsignedAttestation().checkValidity();
    }

    @Override
    public boolean verify() {
        if (!signature.verify(nftAtt.getDerEncoding(), getNFTAttestationVerificationKey())) {
            return false;
        }
        if (!nftAtt.verify()) {
            return false;
        }
        return true;
    }
}