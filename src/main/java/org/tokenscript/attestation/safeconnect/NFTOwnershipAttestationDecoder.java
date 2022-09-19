package org.tokenscript.attestation.safeconnect;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.tokenscript.attestation.ERC721Token;
import org.tokenscript.attestation.ObjectDecoder;

import java.io.IOException;
import java.util.Date;

public class NFTOwnershipAttestationDecoder implements ObjectDecoder<OwnershipAttestationInterface> {
    @Override
    public NFTOwnershipAttestation decode(byte[] encoding) throws IOException {
        ASN1InputStream input = null;
        try {
            input = new ASN1InputStream(encoding);
            ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());

            int ownershipAttCtr = 0;
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(asn1.getObjectAt(ownershipAttCtr++));
            AsymmetricKeyParameter subjectPublicKey = PublicKeyFactory.createKey(subjectPublicKeyInfo);
            DERSequence tokensEnc = DERSequence.convert(
                    ASN1Sequence.getInstance(asn1.getObjectAt(ownershipAttCtr++)));
            ERC721Token[] tokens = new ERC721Token[tokensEnc.size()];
            for (int i = 0; i < tokensEnc.size(); i++) {
                tokens[i] = new ERC721Token(tokensEnc.getObjectAt(i).toASN1Primitive().getEncoded());
            }
            ASN1Sequence validity = DERSequence.convert(
                    ASN1Sequence.getInstance(asn1.getObjectAt(ownershipAttCtr++)));
            ASN1Integer notBeforeEnc = ASN1Integer.getInstance(validity.getObjectAt(0));
            // Multiply with 1000 since the data is stored in seconds and not milliseconds
            Date notBefore = new Date(notBeforeEnc.longValueExact() * 1000);
            ASN1Integer notAfterEnc = ASN1Integer.getInstance(validity.getObjectAt(1));
            Date notAfter = new Date(notAfterEnc.longValueExact() * 1000);
            byte[] decodedContext;
            try {
                decodedContext = ASN1OctetString.getInstance(asn1.getObjectAt(ownershipAttCtr)).getOctets();
                ownershipAttCtr++;
            } catch (Exception e) {
                // Context is not included
                decodedContext = null;
            }
            byte[] context = decodedContext;
            return new NFTOwnershipAttestation(context, tokens, notBefore, notAfter, subjectPublicKey);
        } finally {
            input.close();
        }
    }
}