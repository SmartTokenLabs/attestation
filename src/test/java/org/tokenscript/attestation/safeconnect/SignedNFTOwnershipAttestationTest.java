package org.tokenscript.attestation.safeconnect;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.ERC721Token;
import org.tokenscript.attestation.core.SignatureUtility;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class SignedNFTOwnershipAttestationTest {
    // todo make general test setup fixture and use groovy
    private static final X9ECParameters SUBTLE_CRYPTO_CURVE = SECNamedCurves.getByName("secp256r1"); // NIST P-256
    private static final ERC721Token[] nfts = new ERC721Token[]{
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "25"),
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "26")
    };
    private static AsymmetricCipherKeyPair issuerKeys;
    private static SecureRandom rand;
    private static final byte[] context = new byte[]{0x00};
    private static final long defaultValidity = 60; //seconds
    private static AsymmetricCipherKeyPair subjectECKeys;

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rand.setSeed("seed".getBytes());
        subjectECKeys = SignatureUtility.constructECKeys(SUBTLE_CRYPTO_CURVE, rand);
        issuerKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    }

    @Test
    public void sunshine() {
        SignedNFTOwnershipAttestation att = new SignedNFTOwnershipAttestation(context, subjectECKeys.getPublic(), nfts, defaultValidity, issuerKeys);
        assertTrue(att.checkValidity());
        assertTrue(att.verify());
        assertEquals(context, att.getContext());
        assertEquals(subjectECKeys.getPublic(), att.getSubjectPublicKey());
        assertEquals(issuerKeys.getPublic(), att.getVerificationKey());
        assertArrayEquals(nfts, att.getTokens());
    }

    @Test
    public void testDecoding() throws Exception {
        SignedNFTOwnershipAttestation att = new SignedNFTOwnershipAttestation(context, subjectECKeys.getPublic(), nfts, defaultValidity, issuerKeys);
        SignedOwnershipAttestationDecoder decoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), issuerKeys.getPublic());
        SignedNFTOwnershipAttestation decodedAtt = (SignedNFTOwnershipAttestation) decoder.decode(att.getDerEncoding());
        assertTrue(decodedAtt.checkValidity());
        assertTrue(decodedAtt.verify());
        assertArrayEquals(context, decodedAtt.getContext());
//        assertEquals(subjectECKeys.getPublic(), SignatureUtility.addressFromKey(decodedAtt.getSubjectPublicKey()));
//        assertEquals(SignatureUtility.addressFromKey(issuerKeys.getPublic()), SignatureUtility.addressFromKey(decodedAtt.getVerificationKey()));
        for (int i = 0; i < nfts.length; i++) {
            assertArrayEquals(nfts[i].getDerEncoding(), decodedAtt.getTokens()[i].getDerEncoding());
        }
        assertEquals(nfts.length, decodedAtt.getTokens().length);
        assertEquals(att.getNotBefore(), decodedAtt.getNotBefore());
        assertEquals(att.getNotAfter(), decodedAtt.getNotAfter());
        assertArrayEquals(att.getDerEncoding(), decodedAtt.getDerEncoding());
    }
}
