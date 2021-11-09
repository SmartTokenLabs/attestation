package io.alchemynft.attestation;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.ERC721Token;
import org.tokenscript.attestation.SignedIdentifierAttestation;
import org.tokenscript.attestation.core.ASNEncodable;
import org.tokenscript.attestation.core.Validateable;

public class NFTAttestation implements ASNEncodable, Validateable {
    private static final Logger logger = LogManager.getLogger(NFTAttestation.class);

    private final SignedIdentifierAttestation signedIdentifierAttestation;
    private final ERC721Token[] erc721Tokens;
    private final DERSequence tokens;

    public NFTAttestation(SignedIdentifierAttestation signedIdentifierAttestation, ERC721Token[] nftTokens)
    {
        this.signedIdentifierAttestation = signedIdentifierAttestation;
        this.erc721Tokens = nftTokens;
        ASN1EncodableVector asn1 = new ASN1EncodableVector();
        for (ERC721Token nftToken : nftTokens)
        {
            asn1.add(new DERSequence(nftToken.getTokenVector()));
        }
        this.tokens = new DERSequence(asn1);
    }

    public NFTAttestation(byte[] derEncoding, AsymmetricKeyParameter identifierAttestationVerificationKey) throws IOException {
        ASN1InputStream input = new ASN1InputStream(derEncoding);
        ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
        input.close();
        ASN1Sequence attestationEnc = ASN1Sequence.getInstance(asn1.getObjectAt(0)); //root attestation, should be signed att
        this.signedIdentifierAttestation = new SignedIdentifierAttestation(attestationEnc.getEncoded(), identifierAttestationVerificationKey);

        ASN1Sequence tokensEnc = ASN1Sequence.getInstance(asn1.getObjectAt(1));
        this.tokens = DERSequence.convert(tokensEnc);
        this.erc721Tokens = new ERC721Token[tokens.size()];
        for (int i = 0; i< erc721Tokens.length; i++) {
            erc721Tokens[i] = new ERC721Token(tokens.getObjectAt(i).toASN1Primitive().getEncoded());
        }
    }

    @Override
    public byte[] getDerEncoding() {
        try {
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(ASN1Primitive.fromByteArray(signedIdentifierAttestation.getDerEncoding()));
            res.add(tokens);
            return new DERSequence(res).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public SignedIdentifierAttestation getSignedIdentifierAttestation() {
        return signedIdentifierAttestation;
    }

    public ERC721Token[] getTokens() {
        return erc721Tokens;
    }

    public AlgorithmIdentifier getSigningAlgorithm() {
        return signedIdentifierAttestation.getUnsignedAttestation().getSigningAlgorithm();
    }

    public boolean checkValidity() {
        return signedIdentifierAttestation.checkValidity();
    }

    public boolean verify() {
        return signedIdentifierAttestation.verify();
    }
}
