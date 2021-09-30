package org.twittertip;

import com.alphawallet.token.tools.Numeric;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.HelperTest;
import org.tokenscript.attestation.IdentifierAttestation;
import org.tokenscript.attestation.SignedIdentifierAttestation;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.demo.SmartContract;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class CoSignedIdentifierAttestationTest
{
    private static AsymmetricCipherKeyPair subjectKeys;
    private static AsymmetricCipherKeyPair attestorKeys;
    private static SecureRandom rand;

    static SignedIdentifierAttestation attestation;
    private CoSignedIdentifierAttestation coSignedAttestation;

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rand.setSeed("seed".getBytes());
        subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        attestorKeys = SignatureUtility.constructECKeys(rand);

        IdentifierAttestation att = new IdentifierAttestation("20552167", "https://twitter.com/zhangweiwu", subjectKeys.getPublic());
        assertTrue(att.checkValidity());
        attestation = new SignedIdentifierAttestation(att, attestorKeys);

        System.out.println("SubjectPublicKey's Fingerprint (summarised as Ethereum address):\n" + SignatureUtility.addressFromKey(subjectKeys.getPublic()));
    }

    @Test
    public void testWrappedAttestation() throws Exception
    {
        coSignedAttestation = new CoSignedIdentifierAttestation(attestation, subjectKeys);
        Path p = Files.createTempFile("signed_CoSignedIDAttestation", ".der");

        System.out.println("To check the unsigned NFT attestation, run this:");
        System.out.println("$ openssl asn1parse -inform DER -in " + p.toString());
        Files.write(p, coSignedAttestation.getDerEncoding());

        System.out.println("Wrapped ID Attestation: " + Numeric.toHexString(coSignedAttestation.getDerEncoding()));
        System.out.println("Signed ID Attestation: " + Numeric.toHexString(coSignedAttestation.getUnsignedAttestation().getDerEncoding()));

        //Extract the Ethereum signature
        byte[] sig = coSignedAttestation.getSignature();

        byte[] signedIdentifierBytes = coSignedAttestation.getUnsignedAttestation().getDerEncoding();

        SignedIdentifierAttestation reconstructSignedAtt = new SignedIdentifierAttestation(signedIdentifierBytes, attestorKeys.getPublic());

        //generate SignedIdentifierAttestation from the SignedIdentifierAttestation bytes
        CoSignedIdentifierAttestation reconstructWrapped = new CoSignedIdentifierAttestation(
                reconstructSignedAtt,
                subjectKeys.getPublic(),
                sig);

        assertTrue(reconstructWrapped.verify());

        //Negative test:                                                    v - Changed 1 digit in ID
        IdentifierAttestation att2 = new IdentifierAttestation("20552168", "https://twitter.com/zhangweiwu", subjectKeys.getPublic());
        SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att2, attestorKeys);
        try {
            CoSignedIdentifierAttestation negativeWrapped = new CoSignedIdentifierAttestation(
                    signed,
                    subjectKeys.getPublic(),
                    sig);

            fail(); // should not be able to get here
        } catch (IllegalArgumentException e) {
            //
        }

        //negative 2
        try {
            sig[6] = (byte) (sig[6] + (byte) 0x01);
            reconstructSignedAtt = new SignedIdentifierAttestation(signedIdentifierBytes, attestorKeys.getPublic());
            CoSignedIdentifierAttestation negativeWrapped = new CoSignedIdentifierAttestation(
                    reconstructSignedAtt,
                    subjectKeys.getPublic(),
                    sig);

            fail(); //should not be able to get here
        } catch (IllegalArgumentException e) {
            //
        }
    }

    @Test
    public void testPublicAttestation() {
        assertTrue(attestation.checkValidity());
        assertTrue(attestation.verify());
        assertTrue(SignatureUtility.verifyEthereumSignature(attestation.getUnsignedAttestation().getPrehash(), attestation.getSignature(), attestorKeys.getPublic()));
    }

    @Test
    public void testDecoding() throws Exception {
        IdentifierAttestation att = HelperTest.makeMaximalAtt(subjectKeys.getPublic());
        SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, attestorKeys);
        assertTrue(SignatureUtility.verifyEthereumSignature(att.getPrehash(), signed.getSignature(), attestorKeys.getPublic()));
        assertArrayEquals(att.getPrehash(), signed.getUnsignedAttestation().getPrehash());
        byte[] signedEncoded = signed.getDerEncoding();

        SignedIdentifierAttestation newSigned = new SignedIdentifierAttestation(signedEncoded, attestorKeys.getPublic());
        assertArrayEquals(signed.getDerEncoding(), newSigned.getDerEncoding());
    }
}
