package com.alphawallet.attestation;

import com.alphawallet.attestation.core.ASNEncodable;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.ethereum.ERC721Token;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class NFTAttestation implements ASNEncodable, Validateable {
    private final SignedAttestation att;
    private final ASN1Sequence token;

    public NFTAttestation(SignedAttestation att, ERC721Token nftToken) {
        this.att = att;
        this.token = new DERSequence(nftToken.getTokenVector());
    }

    @Override
    public byte[] getDerEncoding() {
        try {
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(ASN1Primitive.fromByteArray(att.getDerEncoding()));
            res.add(token);
            return new DERSequence(res).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean checkValidity() {
        return att.checkValidity();
    }
}
