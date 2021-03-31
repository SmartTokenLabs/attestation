package com.alphawallet.attestation;

import com.alphawallet.attestation.core.SignatureUtility;
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
        Attestation att = HelperTest.makePublicIdAttestation(subjectKeys.getPublic(), "TW", "@kingmidas");
        attestation = new SignedAttestation(att, attestorKeys);
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
        SignedAttestation newSigned = new SignedAttestation(signedEncoded, issuerKeys.getPublic());
        assertArrayEquals(signed.getDerEncoding(), newSigned.getDerEncoding());
    }
}
