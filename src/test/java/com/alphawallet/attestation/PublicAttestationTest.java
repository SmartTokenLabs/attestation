package com.alphawallet.attestation;

import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.ethereum.ERC721Token;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PublicAttestationTest {
    private static AsymmetricCipherKeyPair subjectKeys;
    private static AsymmetricCipherKeyPair issuerKeys;
    private static AsymmetricCipherKeyPair attestorKeys;
    private static SecureRandom rand;
    private SignedAttestation attestation;
    private SignedNFTAttestation nftAttestation;

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG");
        rand.setSeed("seed".getBytes());
        subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        attestorKeys = SignatureUtility.constructECKeys(rand);
        issuerKeys = SignatureUtility.constructECKeys(rand);
    }

    @BeforeEach
    public void makePublicAttestation()
    {
        Attestation att2 = HelperTest.makePublicIdAttestation(subjectKeys.getPublic(), "TW", "@kingmidas");
        attestation = new SignedAttestation(att2, attestorKeys);
    }

    @Test
    public void testNFTAttestation() throws Exception
    {
        ERC721Token myNFT = new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "25");
        NFTAttestation nftAtt = new NFTAttestation(attestation, myNFT);
        //construct SignedNFTAttestation using subject key
        nftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys);

        //Extract the Ethereum signature
        byte[] sig = nftAttestation.getSignature();

        //generate NFTAttestation from the NFTAttestation bytes
        NFTAttestation nftAttestation2 = new NFTAttestation(nftAtt.getDerEncoding(), attestorKeys.getPublic());

        //check recovered signed attestation within the wrapping
        assertTrue(nftAttestation2.verify());

        //Generate SignedNFTAttestation using the reconstructed NFTAttestation and the extracted Ethereum signature
        SignedNFTAttestation signedNFTAttestation2 = new SignedNFTAttestation(nftAttestation2, subjectKeys.getPublic(), sig);
        assertTrue(signedNFTAttestation2.checkValidity());
    }

    @Test
    public void testPublicAttestation() {
        assertTrue(attestation.checkValidity());
        assertTrue(attestation.verify());
        assertTrue(SignatureUtility.verifyEthereumSignature(attestation.getUnsignedAttestation().getPrehash(), attestation.getSignature(), attestorKeys.getPublic()));
    }

    @Test
    public void testDecoding() throws Exception {
        Attestation att = HelperTest.makeMaximalAtt(subjectKeys.getPublic());
        SignedAttestation signed = new SignedAttestation(att, issuerKeys);
        assertTrue(SignatureUtility.verifyEthereumSignature(att.getPrehash(), signed.getSignature(), issuerKeys.getPublic()));
        assertArrayEquals(att.getPrehash(), signed.getUnsignedAttestation().getPrehash());
        byte[] signedEncoded = signed.getDerEncoding();

        //Fails?
        //SignedAttestation newSigned = new SignedAttestation(signedEncoded, issuerKeys.getPublic());
        //assertArrayEquals(signed.getDerEncoding(), newSigned.getDerEncoding());
    }
}
