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
import java.util.HashMap;
import java.util.Map;

import static org.tokenscript.attestation.core.SignatureUtility.getSigningAlgorithm;


public class SignedEthereumKeyLinkingAttestationDecoder implements ObjectDecoder<SignedEthereumKeyLinkingAttestation> {
    private static final Logger logger = LogManager.getLogger(SignedEthereumKeyLinkingAttestationDecoder.class);
    private final Map<Integer, ObjectDecoder<SignedOwnershipAttestationInterface>> internalDecoders = new HashMap<>();

    public SignedEthereumKeyLinkingAttestationDecoder(ObjectDecoder<SignedOwnershipAttestationInterface> decoder) {
        internalDecoders.put(-1, decoder);
    }

    public SignedEthereumKeyLinkingAttestationDecoder(Map<Integer, ObjectDecoder<SignedOwnershipAttestationInterface>> decoders) {
        this.internalDecoders.putAll(decoders);
    }

    protected void checkAlgorithm(AlgorithmIdentifier algorithmEncoded, AsymmetricKeyParameter verificationKey) {
        if (!algorithmEncoded.equals(getSigningAlgorithm(verificationKey))) {
            throw ExceptionUtil.throwException(logger,
                    new IllegalArgumentException("Algorithm specified is does not work with verification key supplied"));
        }
    }

    @Override
    public SignedEthereumKeyLinkingAttestation decode(byte[] encoding) throws IOException {
        try (ASN1InputStream input = new ASN1InputStream(encoding)) {
            int ctr = 0;
            ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
            DERSequence internalAttEnc = DERSequence.convert(
                    ASN1Sequence.getInstance(asn1.getObjectAt(ctr++)));

            int ownershipAttCtr = 0;
            ASN1OctetString subjectAddressEnc = ASN1OctetString.getInstance(internalAttEnc.getObjectAt(ownershipAttCtr++));
            String subjectAddress = "0x" + Hex.toHexString(subjectAddressEnc.getOctets());

            ASN1TaggedObject taggedAttEnc = ASN1TaggedObject.getInstance(internalAttEnc.getObjectAt(ownershipAttCtr++));
            ASN1Sequence ownershipAttEnc = ASN1Sequence.getInstance(taggedAttEnc.getBaseObject());
            SignedOwnershipAttestationInterface internalAtt;
            // If there is an explicit (single) decoder, then use this, otherwise look at the tag
            if (internalDecoders.size() == 1) {
                internalAtt = internalDecoders.get(internalDecoders.keySet().toArray()[0]).decode(ownershipAttEnc.getEncoded());
            } else {
                internalAtt = internalDecoders.get(taggedAttEnc.getTagNo()).decode(ownershipAttEnc.getEncoded());
            }
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
        }
    }
}
