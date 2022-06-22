package org.tokenscript.attestation.safeconnect;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.ERC721Token;
import org.tokenscript.attestation.core.SignatureUtility;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class SignedNFTOwnershipAttestationTest {
    // todo make general test setup fixture and use groovy
    private static AsymmetricCipherKeyPair subjectKeys;
    private static AsymmetricCipherKeyPair issuerKeys;
    private static SecureRandom rand;
    private static ERC721Token[] nfts;
    private static byte[] context = new byte[] {0x00};

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rand.setSeed("seed".getBytes());
        subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        issuerKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        nfts = new ERC721Token[] {
                new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "25"),
                new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "26")
        };
    }

    @Test
    public void sunshine() {
        SignedNFTOwnershipAttestation att = new SignedNFTOwnershipAttestation(context, subjectKeys.getPublic(), nfts, 60, issuerKeys);
        assertTrue(att.checkValidity());
        assertTrue(att.verify());
        assertEquals(context, att.getContext());
        assertEquals(subjectKeys.getPublic(), att.getSubjectPublicKey());
        assertEquals(issuerKeys.getPublic(), att.getVerificationKey());
        assertArrayEquals(nfts, att.getTokens());
    }

    @Test
    public void testDecoding() throws Exception {
        SignedNFTOwnershipAttestation att = new SignedNFTOwnershipAttestation(context, subjectKeys.getPublic(), nfts, 60, issuerKeys);
        SignedNFTOwnershipAttestation decodedAtt = new SignedNFTOwnershipAttestation(att.getDerEncoding(), issuerKeys.getPublic());
        assertTrue(decodedAtt.checkValidity());
        assertTrue(decodedAtt.verify());
        assertArrayEquals(context, decodedAtt.getContext());
        // todo validate encoding
//        assertEquals(subjectKeys.getPublic(), decodedAtt.getSubjectPublicKey());
//        assertEquals(issuerKeys.getPublic(), decodedAtt.getVerificationKey());
        for (int i = 0; i <nfts.length; i++) {
            assertArrayEquals(nfts[i].getDerEncoding(), decodedAtt.getTokens()[i].getDerEncoding());
        }
        assertEquals(nfts.length, decodedAtt.getTokens().length);
        assertEquals(att.getNotBefore(), decodedAtt.getNotBefore());
        assertEquals(att.getNotAfter(), decodedAtt.getNotAfter());
        assertArrayEquals(att.getDerEncoding(), decodedAtt.getDerEncoding());
    }
}
