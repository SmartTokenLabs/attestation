package org.tokenscript.attestation.safeconnect;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.core.ExceptionUtil;

import java.io.IOException;

import static org.tokenscript.attestation.core.SignatureUtility.getSigningAlgorithm;


public class SignedOwnershipAttestationDecoder implements ObjectDecoder<SignedOwnershipAttestationInterface> {
    private static final Logger logger = LogManager.getLogger(SignedOwnershipAttestationDecoder.class);
    private final AsymmetricKeyParameter verificationKey;
    private final ObjectDecoder<OwnershipAttestationInterface> internalDecoder;

    public SignedOwnershipAttestationDecoder(ObjectDecoder<OwnershipAttestationInterface> decoder, AsymmetricKeyParameter verificationKey) {
        this.verificationKey = verificationKey;
        this.internalDecoder = decoder;
    }

    @Override
    public SignedOwnershipAttestationInterface decode(byte[] encoding) throws IOException {
        try (ASN1InputStream input = new ASN1InputStream(encoding)) {
            ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());

            ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(asn1.getObjectAt(0));
            ASN1Sequence ownershipAttEnc = ASN1Sequence.getInstance(taggedObject.getBaseObject());
            OwnershipAttestationInterface internalAtt = internalDecoder.decode(ownershipAttEnc.getEncoded());

            AlgorithmIdentifier algorithmEncoded = AlgorithmIdentifier.getInstance(asn1.getObjectAt(1));
            ASN1BitString signatureEnc = ASN1BitString.getInstance(asn1.getObjectAt(2));
            byte[] signature = signatureEnc.getBytes();

            if (!algorithmEncoded.equals(getSigningAlgorithm(verificationKey))) {
                throw ExceptionUtil.throwException(logger,
                        new IllegalArgumentException("Algorithm specified is does not work with verification key supplied"));
            }
            if (internalDecoder instanceof NFTOwnershipAttestationDecoder) {
                return new SignedNFTOwnershipAttestation(internalAtt.getContext(), internalAtt.getSubjectPublicKey(), ((NFTOwnershipAttestation) internalAtt).getTokens(), internalAtt.getNotBefore(), internalAtt.getNotAfter(), signature, verificationKey);
            }
            if (internalDecoder instanceof EthereumAddressAttestationDecoder) {
                return new SignedEthereumAddressAttestation(internalAtt.getContext(), internalAtt.getSubjectPublicKey(), ((EthereumAddressAttestation) internalAtt).getSubjectAddress(), internalAtt.getNotBefore(), internalAtt.getNotAfter(), signature, verificationKey);
            }
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Unknown internal attestation format"));
        }
    }
}
