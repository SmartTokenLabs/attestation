package io.alchemynft.attestation;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.SignedIdentifierAttestation;

public class NFTAttestationDecoder implements ObjectDecoder<NFTAttestation> {
  private final AsymmetricKeyParameter identifierAttestationVerificationKey;
  public NFTAttestationDecoder(AsymmetricKeyParameter identifierAttestationVerificationKey) {
    this.identifierAttestationVerificationKey = identifierAttestationVerificationKey;
  }

  @Override
  public NFTAttestation decode(byte[] encoding) throws IOException {
    ASN1InputStream input = new ASN1InputStream(encoding);
    ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
    input.close();
    ASN1Sequence attestationEnc = ASN1Sequence.getInstance(asn1.getObjectAt(0)); //root attestation, should be signed att
    SignedIdentifierAttestation signedIdentifierAttestation = new SignedIdentifierAttestation(attestationEnc.getEncoded(), identifierAttestationVerificationKey);

    ASN1Sequence tokensEnc = ASN1Sequence.getInstance(asn1.getObjectAt(1));
    DERSequence tokens = DERSequence.convert(tokensEnc);
    ERC721Token[] erc721Tokens = new ERC721Token[tokens.size()];
    for (int i = 0; i< erc721Tokens.length; i++) {
      erc721Tokens[i] = new ERC721Token(tokens.getObjectAt(i).toASN1Primitive().getEncoded());
    }
    return new NFTAttestation(signedIdentifierAttestation, erc721Tokens);
  }
}
