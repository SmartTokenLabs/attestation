package org.tokenscript.attestation.safeconnect;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.core.ExceptionUtil;

import java.io.IOException;

import static org.tokenscript.attestation.safeconnect.AbstractSignedOwnershipAttestation.getSigningAlgorithm;

public class SignedEthereumAddressAttestationDecoder implements ObjectDecoder<SignedEthereumAddressAttestation> {
    private static final Logger logger = LogManager.getLogger(SignedNFTOwnershipDecoder.class);
    private final AsymmetricKeyParameter verificationKey;
    private final ObjectDecoder<EthereumAddressAttestation> internalDecoder;

    public SignedEthereumAddressAttestationDecoder(ObjectDecoder<EthereumAddressAttestation> decoder, AsymmetricKeyParameter verificationKey) {
        this.verificationKey = verificationKey;
        this.internalDecoder = decoder;
    }

    @Override
    public SignedEthereumAddressAttestation decode(byte[] encoding) throws IOException {
        ASN1InputStream input = new ASN1InputStream(encoding);
        try {
            ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
            ASN1Sequence ownershipAttEnc = ASN1Sequence.getInstance(asn1.getObjectAt(0));
            EthereumAddressAttestation internalAtt = internalDecoder.decode(ownershipAttEnc.getEncoded());

            AlgorithmIdentifier algorithmEncoded = AlgorithmIdentifier.getInstance(asn1.getObjectAt(1));
            ASN1BitString signatureEnc = ASN1BitString.getInstance(asn1.getObjectAt(2));
            byte[] signature = signatureEnc.getBytes();

            if (!algorithmEncoded.equals(getSigningAlgorithm(verificationKey))) {
                throw ExceptionUtil.throwException(logger,
                        new IllegalArgumentException("Algorithm specified is does not work with verification key supplied"));
            }
            return new SignedEthereumAddressAttestation(internalAtt.getContext(), internalAtt.getSubjectPublicKey(), internalAtt.getSubjectAddress(), internalAtt.getNotBefore(), internalAtt.getNotAfter(), signature, verificationKey);
        } finally {
            input.close();
        }
    }
}
