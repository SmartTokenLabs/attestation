package org.twittertip;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.alphawallet.token.tools.Numeric;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.tokenscript.attestation.HelperTest;
import org.tokenscript.attestation.IdentifierAttestation;
import org.tokenscript.attestation.SignedIdentifierAttestation;
import org.tokenscript.attestation.core.SignatureUtility;

public class CoSignedIdentifierAttestationTest
{
    private static AsymmetricCipherKeyPair subjectKeys;
    private static AsymmetricCipherKeyPair attestorKeys;
    private static SecureRandom rand;

    static SignedIdentifierAttestation attestation;
    private CoSignedIdentifierAttestation coSignedAttestation;
    @Mock
    SignedIdentifierAttestation mockedAttestation;

    @BeforeEach
    public void init() {
        MockitoAnnotations.initMocks(this);
    }

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
        System.out.println("Signed ID Attestation: " + Numeric.toHexString(coSignedAttestation.getWrappedSignedIdentifierAttestation().getDerEncoding()));

        //Extract the Ethereum signature
        byte[] sig = coSignedAttestation.getSignature();

        byte[] signedIdentifierBytes = coSignedAttestation.getWrappedSignedIdentifierAttestation().getDerEncoding();

        SignedIdentifierAttestation reconstructSignedAtt = new SignedIdentifierAttestation(signedIdentifierBytes, attestorKeys.getPublic());

        //generate SignedIdentifierAttestation from the SignedIdentifierAttestation bytes
        CoSignedIdentifierAttestation reconstructWrapped = new CoSignedIdentifierAttestation(
                reconstructSignedAtt,
                subjectKeys.getPublic(),
                sig);

        assertTrue(reconstructWrapped.checkValidity());

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

    @Test
    public void badValidation() {
        Mockito.when(mockedAttestation.verify()).thenReturn(true);
        Mockito.when(mockedAttestation.getDerEncoding()).thenReturn(new byte[] {0x00});
        Mockito.when(mockedAttestation.getSignature()).thenReturn(new byte[] {0x00});
        Mockito.when(mockedAttestation.checkValidity()).thenReturn(false);

        coSignedAttestation = new CoSignedIdentifierAttestation(mockedAttestation, subjectKeys);
        assertTrue(coSignedAttestation.verify());
        assertFalse(coSignedAttestation.checkValidity());
    }

    @Test
    public void badVerification() {
        // We need to return true first, since it is checked in the constructor
        Mockito.when(mockedAttestation.verify()).thenReturn(true).thenReturn(false);
        Mockito.when(mockedAttestation.getDerEncoding()).thenReturn(new byte[] {0x00});
        Mockito.when(mockedAttestation.getSignature()).thenReturn(new byte[] {0x00});
        Mockito.when(mockedAttestation.checkValidity()).thenReturn(true);

        coSignedAttestation = new CoSignedIdentifierAttestation(mockedAttestation, subjectKeys);
        assertFalse(coSignedAttestation.verify());
        assertTrue(coSignedAttestation.checkValidity());
    }
}
