package io.alchemynft.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
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
import org.tokenscript.attestation.ERC721Token;
import org.tokenscript.attestation.HelperTest;
import org.tokenscript.attestation.IdentifierAttestation;
import org.tokenscript.attestation.SignedIdentifierAttestation;
import org.tokenscript.attestation.core.PersonalSignature;
import org.tokenscript.attestation.core.Signature;
import org.tokenscript.attestation.core.SignatureUtility;

public class NFTAttestationTest {
    private static AsymmetricCipherKeyPair subjectKeys;
    private static AsymmetricCipherKeyPair attestorKeys;
    private static SecureRandom rand;
    private static SignedIdentifierAttestation signedIdentifierAtt;
    private static NFTAttestation nftAtt;
    private static IdentifierAttestation att;
    private static ERC721Token[] nfts;

    @Mock
    NFTAttestation mockedNftAttestation;
    @Mock
    SignedIdentifierAttestation mockedSignedIdentifierAtt;

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

        att = new IdentifierAttestation("205521676", "https://twitter.com/zhangweiwu", subjectKeys.getPublic());
        assertTrue(att.checkValidity());
        signedIdentifierAtt = new SignedIdentifierAttestation(att, attestorKeys);
        nfts = new ERC721Token[] {
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "25"),
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "26")
        };
        nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        System.out.println("SubjectPublicKey's Fingerprint (summarised as Ethereum address):\n" + SignatureUtility.addressFromKey(subjectKeys.getPublic()));
    }

    @Test
    public void sunshineV1() {
        sunshine(new SignedNFTAttestationV1(nftAtt, subjectKeys.getPrivate()));
    }

    @Test
    public void sunshineV2() {
        sunshine(new SignedNFTAttestationV2(nftAtt, subjectKeys.getPrivate()));
    }

    public void sunshine(SignedNFTAttestation signedNFTAttestation) {
        assertTrue(signedNFTAttestation.verify());
        assertTrue(signedNFTAttestation.checkValidity());
    }

    @Test
    public void testNFTAttestationV1() throws Exception
    {
        SignedNFTAttestationV1 signedNFTAttestation = new SignedNFTAttestationV1(nftAtt, subjectKeys.getPrivate());
        Path p = Files.createTempFile("unsigned_nftAttestation", ".der");

        System.out.println("To check the unsigned NFT attestation, run this:");
        System.out.println("$ openssl asn1parse -inform DER -in " + p.toString());
        Files.write(p, signedNFTAttestation.getDerEncoding());

        //Extract the Ethereum signature
        Signature sig = signedNFTAttestation.getSignature();

        //generate NFTAttestation from the NFTAttestation bytes
        NFTAttestation nftAttestation2 = new NFTAttestation(nftAtt.getDerEncoding(),
            attestorKeys.getPublic());

        //check recovered signed attestation within the wrapping
        assertTrue(nftAttestation2.verify());

        //Generate SignedNFTAttestation using the reconstructed NFTAttestation and the extracted Ethereum signature
        SignedNFTAttestationV1 signedNFTAttestation2 = new SignedNFTAttestationV1(nftAttestation2, sig);
        assertTrue(signedNFTAttestation2.checkValidity());
        assertTrue(signedNFTAttestation.checkValidity());
        assertArrayEquals(signedNFTAttestation2.getUnsignedAttestation().getDerEncoding(), nftAtt.getDerEncoding());
        assertArrayEquals(signedNFTAttestation2.getDerEncoding(), signedNFTAttestation.getDerEncoding());
    }

    @Test
    public void testNFTAttestationV2() throws Exception {
        SignedNFTAttestation signedNFTAttestation = new SignedNFTAttestationV2(nftAtt, subjectKeys.getPrivate());
        Path p = Files.createTempFile("unsigned_nftAttestation", ".der");

        System.out.println("To check the unsigned NFT attestation, run this:");
        System.out.println("$ openssl asn1parse -inform DER -in " + p.toString());
        Files.write(p, signedNFTAttestation.getDerEncoding());

        //generate NFTAttestation from the NFTAttestation bytes
        NFTAttestation nftAttestation2 = new NFTAttestation(nftAtt.getDerEncoding(),
            attestorKeys.getPublic());

        //check recovered signed attestation within the wrapping
        assertTrue(nftAttestation2.verify());
    }

    @Test
    public void consistentEncodingV1() throws Exception {
        SignedNFTAttestationV1 signedNFTAttestation = new SignedNFTAttestationV1(nftAtt, subjectKeys.getPrivate());
        SignedNFTAttestationV1 decodedNFTAtt = new SignedNFTAttestationV1(signedNFTAttestation.getDerEncoding(), attestorKeys.getPublic());
        assertTrue(decodedNFTAtt.verify());
        assertTrue(decodedNFTAtt.checkValidity());
        assertArrayEquals(signedNFTAttestation.getSignature().getRawSignature(), decodedNFTAtt.getSignature().getRawSignature());
        assertEquals(SignatureUtility.addressFromKey(signedNFTAttestation.getNFTAttestationVerificationKey()),
            SignatureUtility.addressFromKey(signedNFTAttestation.getNFTAttestationVerificationKey()));
        assertArrayEquals(signedNFTAttestation.getDerEncoding(), decodedNFTAtt.getDerEncoding());
    }

    @Test
    public void consistentEncodingV2() throws Exception {
        SignedNFTAttestationV2 signedNFTAttestation = new SignedNFTAttestationV2(nftAtt, subjectKeys.getPrivate());
        SignedNFTAttestationV2 decodedNFTAtt = new SignedNFTAttestationV2(signedNFTAttestation.getSignedEIP712(), attestorKeys.getPublic());
        assertTrue(decodedNFTAtt.verify());
        assertTrue(decodedNFTAtt.checkValidity());
        assertEquals(signedNFTAttestation.getSignature(), decodedNFTAtt.getSignature());
        assertEquals(SignatureUtility.addressFromKey(signedNFTAttestation.getNFTAttestationVerificationKey()),
            SignatureUtility.addressFromKey(signedNFTAttestation.getNFTAttestationVerificationKey()));
        assertEquals(signedNFTAttestation.getSignedEIP712(), decodedNFTAtt.getSignedEIP712());
        assertArrayEquals(signedNFTAttestation.getUnsignedAttestation().getDerEncoding(),
            decodedNFTAtt.getDerEncoding());
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
    public void testInvalidEncoding() {
        Mockito.when(mockedNftAttestation.getDerEncoding()).thenReturn(new byte[] {0x42});
        Mockito.when(mockedNftAttestation.getSignedIdentifierAttestation()).thenReturn(signedIdentifierAtt);
        Exception e = assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestationV2(mockedNftAttestation,
            subjectKeys.getPrivate()));
        assertEquals("Could not decode underlying NFTAttestation", e.getMessage());
    }

    @Test
    public void badSignatureV1() {
        Signature wrongSignature = new PersonalSignature(subjectKeys.getPrivate(), "something wrong".getBytes(
            StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestationV1(nftAtt, wrongSignature));
    }

    @Test
    public void badSigningKeyV1() {
        AsymmetricCipherKeyPair notAttestedKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestationV1(nftAtt, notAttestedKeys.getPrivate()));
    }
    @Test
    public void badSigningKeyV2() {
        AsymmetricCipherKeyPair notAttestedKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestationV2(nftAtt, notAttestedKeys.getPrivate()));
    }

    @Test
    public void badNftAttestationV1() {
        Mockito.when(mockedNftAttestation.verify()).thenReturn(false);
        Mockito.when(mockedNftAttestation.getDerEncoding()).thenReturn(new byte[] {0x42});
        assertThrows(RuntimeException.class, ()-> new SignedNFTAttestationV1(mockedNftAttestation, subjectKeys.getPrivate()));
    }
    @Test
    public void badNftAttestationV2() {
        Mockito.when(mockedNftAttestation.verify()).thenReturn(false);
        Mockito.when(mockedNftAttestation.getDerEncoding()).thenReturn(new byte[] {0x42});
        assertThrows(RuntimeException.class, ()-> new SignedNFTAttestationV2(mockedNftAttestation, subjectKeys.getPrivate()));
    }

    @Test
    public void unverifiableSignedIdentifierAttV1() {
        Mockito.when(mockedSignedIdentifierAtt.verify()).thenReturn(false);
        Mockito.when(mockedSignedIdentifierAtt.getDerEncoding()).thenReturn(nftAtt.getDerEncoding());
        Mockito.when(mockedSignedIdentifierAtt.getUnsignedAttestation()).thenReturn(
            att);
        NFTAttestation mockedNftAtt = new NFTAttestation(mockedSignedIdentifierAtt, nfts);
        assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestationV1(mockedNftAtt, subjectKeys.getPrivate()));
    }

    @Test
    public void unverifiableSignedIdentifierAttV2() {
        Mockito.when(mockedSignedIdentifierAtt.verify()).thenReturn(false);
        Mockito.when(mockedSignedIdentifierAtt.getDerEncoding()).thenReturn(nftAtt.getDerEncoding());
        Mockito.when(mockedSignedIdentifierAtt.getUnsignedAttestation()).thenReturn(
            att);
        NFTAttestation mockedNftAtt = new NFTAttestation(mockedSignedIdentifierAtt, nfts);
        assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestationV1(mockedNftAtt, subjectKeys.getPrivate()));
    }

    @Test
    public void invalidSignedIdentifierAttV1() throws Exception {
        NFTAttestation realNftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        IdentifierAttestation identifierAttestation =  new IdentifierAttestation("205521676", "https://twitter.com/zhangweiwu", subjectKeys.getPublic());
        Mockito.when(mockedSignedIdentifierAtt.verify()).thenReturn(true);
        Mockito.when(mockedSignedIdentifierAtt.checkValidity()).thenReturn(false);
        Mockito.when(mockedSignedIdentifierAtt.getDerEncoding()).thenReturn(realNftAtt.getDerEncoding());
        Mockito.when(mockedSignedIdentifierAtt.getUnsignedAttestation()).thenReturn(identifierAttestation);
        NFTAttestation nftAtt = new NFTAttestation(mockedSignedIdentifierAtt, nfts);
        SignedNFTAttestation newSignedNftAttestation = new SignedNFTAttestationV1(nftAtt, subjectKeys.getPrivate());
        assertTrue(newSignedNftAttestation.verify());
        assertFalse(newSignedNftAttestation.checkValidity());
    }

    @Test
    public void invalidSignedIdentifierAttV2() throws Exception {
        AsymmetricCipherKeyPair otherKeys = SignatureUtility.constructECKeys(rand);
        IdentifierAttestation identifierAttestation =  new IdentifierAttestation("205521676", "https://twitter.com/zhangweiwu", otherKeys.getPublic());
        SignedIdentifierAttestation signedIdentifierAttestation = new SignedIdentifierAttestation(identifierAttestation, attestorKeys);
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAttestation, nfts);
        Exception e = assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestationV2(nftAtt, subjectKeys.getPrivate()));
        assertEquals("The NFTAttestation is invalid", e.getMessage());
    }
}
