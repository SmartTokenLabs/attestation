package org.twittertip;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.SignedIdentifierAttestation;
import org.tokenscript.attestation.core.ASNEncodable;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.Validateable;
import org.tokenscript.attestation.core.Verifiable;


public class CoSignedIdentifierAttestation implements ASNEncodable, Verifiable, Validateable {
    private final SignedIdentifierAttestation att;
    private final byte[] signature;
    private final AsymmetricKeyParameter attestationVerificationKey;
    private static final Logger logger = LogManager.getLogger(SignedIdentifierAttestation.class);

    public CoSignedIdentifierAttestation(SignedIdentifierAttestation att, AsymmetricCipherKeyPair subjectSigningKey) {
        this.att = att;
        this.signature = SignatureUtility.signPersonalMsgWithEthereum(att.getDerEncoding(), subjectSigningKey.getPrivate());
        this.attestationVerificationKey = subjectSigningKey.getPublic();
        if (!verify()) {
            throw new IllegalArgumentException("The signature is not valid");
        }
    }

    /**
     * Constructor used for when we supply the signature separately
     */
    public CoSignedIdentifierAttestation(SignedIdentifierAttestation att, AsymmetricKeyParameter subjectPublicKey, byte[] signature) {
        this.att = att;
        this.signature = signature;
        this.attestationVerificationKey = subjectPublicKey;
        if (!verify()) {
            throw new IllegalArgumentException("The signature is not valid");
        }
    }

    public SignedIdentifierAttestation getWrappedSignedIdentifierAttestation() {
        return att;
    }

    public byte[] getSignature() {
        return signature;
    }

    /**
     * Returns the public key of the attestation signer
     */
    public AsymmetricKeyParameter getAttestationVerificationKey() { return attestationVerificationKey; }

    @Override
    public byte[] getDerEncoding() {
        return constructSignedAttestation(this.att, this.signature);
    }

    static byte[] constructSignedAttestation(SignedIdentifierAttestation unsignedAtt, byte[] signature) {
        try {
            byte[] rawAtt = unsignedAtt.getDerEncoding();
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(ASN1Primitive.fromByteArray(rawAtt));
            res.add(unsignedAtt.getUnsignedAttestation().getSigningAlgorithm());
            res.add(new DERBitString(signature));
            return new DERSequence(res).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean checkValidity() {
        if (!getWrappedSignedIdentifierAttestation().checkValidity()) {
            logger.error("Could not verify wrapped SignedIdentifier Attestation");
            return false;
        } else if (!verify()) {
            return false;
        } else {
            return true;
        }
    }

    @Override
    public boolean verify() {
        try {
            if (!SignatureUtility.verifyPersonalEthereumSignature(att.getDerEncoding(), signature, attestationVerificationKey)) {
                logger.error("Could not verify signature");
                return false;
            }
        } catch (Exception e) {
            logger.error("Could not decode the signature");
            return false;
        }
        return true;
    }
}
