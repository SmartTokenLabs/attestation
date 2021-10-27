package io.alchemynft.attestation;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
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

    private final NFTAttestation att;
    private final Signature signature;
    private final AsymmetricKeyParameter attestationVerificationKey;

    public SignedNFTAttestation(NFTAttestation att, AsymmetricCipherKeyPair subjectSigningKey) {
        this.att = att;
        this.attestationVerificationKey = subjectSigningKey.getPublic();
        this.signature = new PersonalSignature(subjectSigningKey, att.getDerEncoding());

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
        if (!verify()) {
            ExceptionUtil.throwException(logger, new IllegalArgumentException("The signature is not valid"));
        }
    }

    public SignedNFTAttestation(byte[] derEncoding, AsymmetricKeyParameter identifierAttestationVerificationKey) throws IOException {
        ASN1InputStream input = new ASN1InputStream(derEncoding);
        ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
        ASN1Sequence nftEncoding = ASN1Sequence.getInstance(asn1.getObjectAt(0));
        this.att = new NFTAttestation(nftEncoding.getEncoded(), identifierAttestationVerificationKey);
        // todo this actually not used
        AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(asn1.getObjectAt(1));
        DERBitString signatureEnc = DERBitString.getInstance(asn1.getObjectAt(2));
        this.signature = new PersonalSignature(signatureEnc.getBytes());
        this.attestationVerificationKey = getKeyFromAttestation();
        input.close();
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
        return constructSignedAttestation(this.att, this.signature.getRawSignature());
    }

    static byte[] constructSignedAttestation(NFTAttestation unsignedAtt, byte[] signature) {
        try {
            byte[] rawAtt = unsignedAtt.getDerEncoding();
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(ASN1Primitive.fromByteArray(rawAtt));
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