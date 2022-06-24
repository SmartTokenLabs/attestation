package org.tokenscript.attestation.safeconnect;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.core.SignatureUtility;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class SignedEthereumAddressAttestationTest {
    // todo make general test setup fixture and use groovy
    private static final X9ECParameters SUBTLE_CRYPTO_CURVE = SECNamedCurves.getByName("secp256r1"); // NIST P-256
    private static final byte[] context = new byte[]{0x00};
    private static final String address = "0x0102030405060708091011121314151617181920";
    private static final long defaultValidity = 60; //seconds
    private static AsymmetricCipherKeyPair issuerKeys;
    private static SecureRandom rand;
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
        SignedEthereumAddressAttestation att = new SignedEthereumAddressAttestation(context, subjectECKeys.getPublic(), address, defaultValidity, issuerKeys);
        assertTrue(att.checkValidity());
        assertTrue(att.verify());
        assertEquals(context, att.getContext());
        assertEquals(subjectECKeys.getPublic(), att.getSubjectPublicKey());
        assertEquals(issuerKeys.getPublic(), att.getVerificationKey());
        assertEquals(address, att.getSubjectAddress());
    }

    @Test
    public void testDecoding() throws Exception {
        SignedEthereumAddressAttestation att = new SignedEthereumAddressAttestation(context, subjectECKeys.getPublic(), address, defaultValidity, issuerKeys);
        SignedEthereumAddressAttestationDecoder decoder = new SignedEthereumAddressAttestationDecoder(new EthereumAddressAttestationDecoder(), issuerKeys.getPublic());
        SignedEthereumAddressAttestation decodedAtt = decoder.decode(att.getDerEncoding());
        assertTrue(decodedAtt.checkValidity());
        assertTrue(decodedAtt.verify());
        assertArrayEquals(context, decodedAtt.getContext());
//        assertEquals(subjectECKeys.getPublic(), SignatureUtility.addressFromKey(decodedAtt.getSubjectPublicKey()));
//        assertEquals(SignatureUtility.addressFromKey(issuerKeys.getPublic()), SignatureUtility.addressFromKey(decodedAtt.getVerificationKey()));
        assertEquals(att.getNotBefore(), decodedAtt.getNotBefore());
        assertEquals(att.getNotAfter(), decodedAtt.getNotAfter());
        assertArrayEquals(att.getDerEncoding(), decodedAtt.getDerEncoding());
    }
}
