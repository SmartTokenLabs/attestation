package com.alphawallet.attestation;

import com.alphawallet.attestation.core.ASNEncodable;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.ethereum.ERC721Token;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.io.IOException;

public class NFTAttestation implements ASNEncodable, Validateable {
    private final SignedAttestation att;
    private final ASN1Sequence token;

    public NFTAttestation(SignedAttestation att, ERC721Token nftToken)
    {
        this.att = att;
        this.token = new DERSequence(nftToken.getTokenVector());
    }

    public NFTAttestation(byte[] derEncoding, AsymmetricKeyParameter signingPublicKey) throws IOException {
        ASN1InputStream input = new ASN1InputStream(derEncoding);
        ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());

        ASN1Sequence attestationEnc = ASN1Sequence.getInstance(asn1.getObjectAt(0)); //root attestation, should be signed att
        this.att = new SignedAttestation(attestationEnc.getEncoded(), signingPublicKey);
        this.token = ASN1Sequence.getInstance(asn1.getObjectAt(1)); //Tokens
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

    public byte[] getPreHash() {
        return SignatureUtility.convertToPersonalEthMessage(getDerEncoding());
    }

    public boolean checkValidity() {
        return att.checkValidity();
    }

    public boolean verify() {
        return att.verify();
    }
}
