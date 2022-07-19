package org.tokenscript.attestation.safeconnect;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.core.ExceptionUtil;

import java.io.IOException;
import java.util.Date;

import static org.tokenscript.attestation.core.SignatureUtility.getSigningAlgorithm;


public class SignedEthereumKeyLinkingAttestationDecoder implements ObjectDecoder<SignedEthereumKeyLinkingAttestation> {
    private static final Logger logger = LogManager.getLogger(SignedEthereumKeyLinkingAttestationDecoder.class);
    private final ObjectDecoder<SignedOwnershipAttestationInterface> internalDecoder;

    public SignedEthereumKeyLinkingAttestationDecoder(ObjectDecoder<SignedOwnershipAttestationInterface> decoder) {
        this.internalDecoder = decoder;
    }

    protected void checkAlgorithm(AlgorithmIdentifier algorithmEncoded, AsymmetricKeyParameter verificationKey) {
        if (!algorithmEncoded.equals(getSigningAlgorithm(verificationKey))) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Algorithm specified is does not work with verification key supplied"));
        }
    }

    @Override
    public SignedEthereumKeyLinkingAttestation decode(byte[] encoding) throws IOException {
        ASN1InputStream input = null;
        try {
            int ctr = 0;
            input = new ASN1InputStream(encoding);
            ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
            DERSequence internalAttEnc = DERSequence.convert(
                    ASN1Sequence.getInstance(asn1.getObjectAt(ctr++)));

            int ownershipAttCtr = 0;
            ASN1OctetString subjectAddressEnc = ASN1OctetString.getInstance(internalAttEnc.getObjectAt(ownershipAttCtr++));
            String subjectAddress = "0x" + Hex.toHexString(subjectAddressEnc.getOctets());
            ASN1Sequence ownershipAttEnc = ASN1Sequence.getInstance(internalAttEnc.getObjectAt(ownershipAttCtr++));
            SignedOwnershipAttestationInterface internalAtt = internalDecoder.decode(ownershipAttEnc.getEncoded());
            ASN1Sequence validity = DERSequence.convert(
                    ASN1Sequence.getInstance(internalAttEnc.getObjectAt(ownershipAttCtr++)));
            ASN1Integer notBeforeEnc = ASN1Integer.getInstance(validity.getObjectAt(0));
            // Multiply with 1000 since the data is stored in seconds and not milliseconds
            Date notBefore = new Date(notBeforeEnc.longValueExact() * 1000);
            ASN1Integer notAfterEnc = ASN1Integer.getInstance(validity.getObjectAt(1));
            Date notAfter = new Date(notAfterEnc.longValueExact() * 1000);
            byte[] decodedContext;
            try {
                decodedContext = ASN1OctetString.getInstance(internalAttEnc.getObjectAt(ownershipAttCtr)).getOctets();
                ownershipAttCtr++;
            } catch (Exception e) {
                // Context is not included
                decodedContext = null;
            }
            byte[] context = decodedContext;

            checkAlgorithm(AlgorithmIdentifier.getInstance(asn1.getObjectAt(ctr++)), internalAtt.getSubjectPublicKey());
            ASN1BitString signatureEnc = ASN1BitString.getInstance(asn1.getObjectAt(ctr++));
            byte[] signature = signatureEnc.getBytes();

            return new SignedEthereumKeyLinkingAttestation(context, subjectAddress, notBefore, notAfter, internalAtt, signature);
        } finally {
            input.close();
        }
    }
}
