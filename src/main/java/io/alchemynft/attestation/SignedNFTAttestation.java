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
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.tokenscript.attestation.core.ASNEncodable;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.Validateable;
import org.tokenscript.attestation.core.Verifiable;

public class SignedNFTAttestation implements ASNEncodable, Verifiable, Validateable {
    private static final Logger logger = LogManager.getLogger(SignedNFTAttestation.class);
    public static final int DEFAULT_SIGNING_VERSION = 2;

    private final NFTAttestation att;
    private final int signingVersion;
    private final Signature signature;
    private final AsymmetricKeyParameter attestationVerificationKey;

    public SignedNFTAttestation(NFTAttestation att, AsymmetricCipherKeyPair subjectSigningKey) {
        this(att, subjectSigningKey, DEFAULT_SIGNING_VERSION);
    }

    public SignedNFTAttestation(NFTAttestation att, AsymmetricCipherKeyPair subjectSigningKey, int signingVersion) {
        this.att = att;
        this.attestationVerificationKey = subjectSigningKey.getPublic();
        this.signature =  makeSignature(subjectSigningKey, signingVersion);
        this.signingVersion = signingVersion;

        if (!verify()) {
            ExceptionUtil.throwException(logger, new IllegalArgumentException("The signature is not valid"));
        }
    }

    /**
     * Constructor used for when we supply the signature separately
     */
    public SignedNFTAttestation(NFTAttestation att, Signature signature) {
        this.att = att;
        this.attestationVerificationKey = getKeyFromAttestation();
        this.signature = signature;
        this.signingVersion = determineSigningVersion();
        if (!verify()) {
            ExceptionUtil.throwException(logger, new IllegalArgumentException("The signature is not valid"));
        }
    }

    public SignedNFTAttestation(byte[] derEncoding, AsymmetricKeyParameter identifierAttestationVerificationKey) throws IOException {
        ASN1InputStream input = new ASN1InputStream(derEncoding);
        ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
        input.close();
        int currentPos = 0;
        ASN1Sequence nftEncoding = ASN1Sequence.getInstance(asn1.getObjectAt(currentPos++));
        this.att = new NFTAttestation(nftEncoding.getEncoded(), identifierAttestationVerificationKey);
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
        this.attestationVerificationKey = getKeyFromAttestation();
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
            return new CompressedMsgSignature(encodedBytes);
        } else {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Unknown signing version"));
        }
    }

    Signature makeSignature(AsymmetricCipherKeyPair keys, int signingVersion) {
        if (signingVersion == 1) {
            return new PersonalSignature(keys, att.getDerEncoding());
        }
        else if (signingVersion == 2) {
            return new CompressedMsgSignature(keys, att.getDerEncoding());
        } else {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Unknown signing version"));
        }
    }

    private AsymmetricKeyParameter getKeyFromAttestation() {
        AsymmetricKeyParameter key = null;
        try {
            key = PublicKeyFactory.createKey(
                att.getSignedIdentifierAttestation().getUnsignedAttestation()
                    .getSubjectPublicKeyInfo());
        } catch (IOException e) {
            ExceptionUtil.makeRuntimeException(logger, "Could not restore key from signed signed attestation", e);
        }
        return key;
    }

    public NFTAttestation getUnsignedAttestation() {
        return att;
    }

    public Signature getSignature() {
        return signature;
    }

    /**
     * Returns the public key of the attestation signer
     */
    public AsymmetricKeyParameter getAttestationVerificationKey() { return attestationVerificationKey; }

    @Override
    public byte[] getDerEncoding() {
        return constructSignedAttestation(this.att, this.signingVersion, this.signature.getRawSignature());
    }

    static byte[] constructSignedAttestation(NFTAttestation unsignedAtt, int signingVersion, byte[] signature) {
        try {
            byte[] rawAtt = unsignedAtt.getDerEncoding();
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(ASN1Primitive.fromByteArray(rawAtt));
            res.add(new ASN1Integer(signingVersion));
            res.add(unsignedAtt.getSigningAlgorithm());
            res.add(new DERBitString(signature));
            return new DERSequence(res).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean checkValidity() {
        return getUnsignedAttestation().checkValidity();
    }

    @Override
    public boolean verify() {
        if (!signature.verify(att.getDerEncoding(), attestationVerificationKey)) {
            return false;
        }
        if (!att.verify()) {
            return false;
        }
        // Verify that signature is done using thew right key
        if (!SignatureUtility.addressFromKey(attestationVerificationKey).equals(
            SignatureUtility.addressFromKey(getKeyFromAttestation()))) {
            return false;
        }
        return true;
    }
}