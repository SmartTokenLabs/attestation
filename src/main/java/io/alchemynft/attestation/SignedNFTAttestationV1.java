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
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.PersonalSignature;
import org.tokenscript.attestation.core.Signature;

public class SignedNFTAttestationV1 implements SignedNFTAttestation {
    private static final Logger logger = LogManager.getLogger(SignedNFTAttestationV1.class);

    private final NFTAttestation nftAtt;
    private final Signature signature;

    public SignedNFTAttestationV1(NFTAttestation NftAtt, AsymmetricKeyParameter subjectSigningKey) {
        this.nftAtt = NftAtt;
        this.signature =  new PersonalSignature(subjectSigningKey, NftAtt.getDerEncoding());

        if (!verify()) {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("The signature is not valid"));
        }
    }

    /**
     * Constructor used for when we supply the signature separately
     */
    public SignedNFTAttestationV1(NFTAttestation NftAtt, Signature signature) {
        this.nftAtt = NftAtt;
        this.signature = signature;
        if (!verify()) {
            throw ExceptionUtil.throwException(logger, new IllegalArgumentException("The signature is not valid"));
        }
    }

    public SignedNFTAttestationV1(byte[] derEncoding, AsymmetricKeyParameter identifierAttestationVerificationKey) throws IOException {
        ASN1InputStream input = new ASN1InputStream(derEncoding);
        ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
        input.close();
        int currentPos = 0;
        ASN1Sequence nftEncoding = ASN1Sequence.getInstance(asn1.getObjectAt(currentPos++));
        this.nftAtt = new NFTAttestation(nftEncoding.getEncoded(), identifierAttestationVerificationKey);
        // todo this actually not used
        AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(asn1.getObjectAt(currentPos++));
        DERBitString signatureEnc = DERBitString.getInstance(asn1.getObjectAt(currentPos++));
        this.signature = new PersonalSignature(signatureEnc.getBytes());
    }

    @Override
    public NFTAttestation getUnsignedAttestation() {
        return nftAtt;
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
        if (!signature.verify(nftAtt.getDerEncoding(), getNFTAttestationVerificationKey())) {
            return false;
        }
        if (!nftAtt.verify()) {
            return false;
        }
        return true;
    }
}