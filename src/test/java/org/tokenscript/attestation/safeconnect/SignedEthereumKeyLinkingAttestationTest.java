package org.tokenscript.attestation.safeconnect;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.ERC721Token;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.core.SignatureUtility;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class SignedEthereumKeyLinkingAttestationTest {
    // todo make general test setup fixture and use groovy
    private static final X9ECParameters SUBTLE_CRYPTO_CURVE = SECNamedCurves.getByName("secp256r1"); // NIST P-256
    private static final byte[] context = new byte[]{0x00};
    private static final String address = "0x0102030405060708091011121314151617181920";
    private static final long defaultValidity = 60; //seconds
    private static final ERC721Token[] nfts = new ERC721Token[]{
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "25"),
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "26")
    };
    private static AsymmetricCipherKeyPair subjectECKeys;
    private static AsymmetricCipherKeyPair issuerKeys;
    private static SecureRandom rand;
    private static SignedOwnershipAttestationInterface internalAtt;

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rand.setSeed("seed".getBytes());
        subjectECKeys = SignatureUtility.constructECKeys(SUBTLE_CRYPTO_CURVE, rand);
        issuerKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        internalAtt = new SignedNFTOwnershipAttestation(context, subjectECKeys.getPublic(), nfts, defaultValidity, issuerKeys);
    }

    @Test
    public void sunshine() throws Exception {
        SignedEthereumKeyLinkingAttestation att = new SignedEthereumKeyLinkingAttestation(context, address, defaultValidity, internalAtt, subjectECKeys);
        assertTrue(att.checkValidity());
        assertTrue(att.verify());
        assertArrayEquals(context, att.getContext());
        assertEquals(address, att.getSubjectAddress());
        //todo
//        assertEquals(issuerKeys.getPublic(), att.getVerificationKey());
        assertArrayEquals(internalAtt.getDerEncoding(), att.getOwnershipAttestation().getDerEncoding());
    }

    @Test
    public void testDecoding() throws Exception {
        SignedEthereumKeyLinkingAttestation att = new SignedEthereumKeyLinkingAttestation(context, address, defaultValidity, internalAtt, subjectECKeys);
        ObjectDecoder<SignedOwnershipAttestationInterface> internalDecoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), issuerKeys.getPublic());
        SignedEthereumKeyLinkingAttestationDecoder decoder = new SignedEthereumKeyLinkingAttestationDecoder(internalDecoder);
        SignedEthereumKeyLinkingAttestation decodedAtt = decoder.decode(att.getDerEncoding());
        assertTrue(decodedAtt.checkValidity());
        assertTrue(decodedAtt.verify());
        assertArrayEquals(context, decodedAtt.getContext());
        assertEquals(address, decodedAtt.getSubjectAddress());
//        assertEquals(SignatureUtility.addressFromKey(issuerKeys.getPublic()), SignatureUtility.addressFromKey(decodedAtt.getVerificationKey()));
        assertArrayEquals(internalAtt.getDerEncoding(), att.getOwnershipAttestation().getDerEncoding());
        assertEquals(att.getNotBefore(), decodedAtt.getNotBefore());
        assertEquals(att.getNotAfter(), decodedAtt.getNotAfter());
        assertArrayEquals(att.getDerEncoding(), decodedAtt.getDerEncoding());
    }
}
