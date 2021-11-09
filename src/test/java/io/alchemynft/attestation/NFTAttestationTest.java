package io.alchemynft.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
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
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.URLUtility;

public class NFTAttestationTest {
    private static AsymmetricCipherKeyPair subjectKeys;
    private static AsymmetricCipherKeyPair issuerKeys;
    private static AsymmetricCipherKeyPair attestorKeys;
    private static SecureRandom rand;
    static SignedIdentifierAttestation signedIdentifierAtt;
    private static SignedNFTAttestation signedNftAttestation;
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
        issuerKeys = SignatureUtility.constructECKeys(rand);

        IdentifierAttestation att = new IdentifierAttestation("205521676", "https://twitter.com/zhangweiwu", subjectKeys.getPublic());
        assertTrue(att.checkValidity());
        signedIdentifierAtt = new SignedIdentifierAttestation(att, attestorKeys);
        nfts = new ERC721Token[] {
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "25"),
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "26")
        };
        System.out.println("SubjectPublicKey's Fingerprint (summarised as Ethereum address):\n" + SignatureUtility.addressFromKey(subjectKeys.getPublic()));
    }

    @Test
    public void sunshine() {
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        //construct SignedNFTAttestation using subject key
        signedNftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys);
        assertTrue(signedNftAttestation.verify());
        assertTrue(signedNftAttestation.checkValidity());
    }

    @Test
    public void testNFTAttestation() throws Exception
    {
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        //construct SignedNFTAttestation using subject key
        signedNftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys);
        Path p = Files.createTempFile("unsigned_nftAttestation", ".der");

        System.out.println("To check the unsigned NFT attestation, run this:");
        System.out.println("$ openssl asn1parse -inform DER -in " + p.toString());
        Files.write(p, signedNftAttestation.getDerEncoding());

        //Extract the Ethereum signature
        Signature sig = signedNftAttestation.getSignature();

        //generate NFTAttestation from the NFTAttestation bytes
        NFTAttestation nftAttestation2 = new NFTAttestation(nftAtt.getDerEncoding(),
            attestorKeys.getPublic());

        //check recovered signed attestation within the wrapping
        assertTrue(nftAttestation2.verify());

        //Generate SignedNFTAttestation using the reconstructed NFTAttestation and the extracted Ethereum signature
        SignedNFTAttestation signedNFTAttestation2 = new SignedNFTAttestation(nftAttestation2, sig);
        assertTrue(signedNFTAttestation2.checkValidity());
        assertTrue(signedNftAttestation.checkValidity());
        assertArrayEquals(signedNFTAttestation2.getUnsignedAttestation().getDerEncoding(), nftAtt.getDerEncoding());
        assertArrayEquals(signedNFTAttestation2.getDerEncoding(), signedNftAttestation.getDerEncoding());
    }

    @Test
    public void consistentEncoding() throws IOException {
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        signedNftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys);
        SignedNFTAttestation decodedNFTAtt = new SignedNFTAttestation(signedNftAttestation.getDerEncoding(), attestorKeys.getPublic());
        assertTrue(decodedNFTAtt.verify());
        assertTrue(decodedNFTAtt.checkValidity());
        assertArrayEquals(signedNftAttestation.getDerEncoding(), decodedNFTAtt.getDerEncoding());
    }

    @Test
    public void testGetters() throws IOException {
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        //construct SignedNFTAttestation using subject key
        signedNftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys);
        assertEquals(SignatureUtility.addressFromKey(signedNftAttestation.getAttestationVerificationKey()),
            SignatureUtility.addressFromKey(subjectKeys.getPublic()));
        assertArrayEquals(nftAtt.getTokens(), nfts);
    }

    @Test
    public void testPublicAttestation() {
        assertTrue(signedIdentifierAtt.checkValidity());
        assertTrue(signedIdentifierAtt.verify());
        assertTrue(SignatureUtility.verifyEthereumSignature(
            signedIdentifierAtt.getUnsignedAttestation().getPrehash(), signedIdentifierAtt.getSignature(), attestorKeys.getPublic()));
    }

    @Test
    public void testDecoding() throws Exception {
        IdentifierAttestation att = HelperTest.makeMaximalAtt(subjectKeys.getPublic());
        SignedIdentifierAttestation signed = new SignedIdentifierAttestation(att, issuerKeys);
        assertTrue(SignatureUtility.verifyEthereumSignature(att.getPrehash(), signed.getSignature(), issuerKeys.getPublic()));
        assertArrayEquals(att.getPrehash(), signed.getUnsignedAttestation().getPrehash());
        byte[] signedEncoded = signed.getDerEncoding();

        SignedIdentifierAttestation newSigned = new SignedIdentifierAttestation(signedEncoded, issuerKeys.getPublic());
        assertArrayEquals(signed.getDerEncoding(), newSigned.getDerEncoding());
    }

    @Test
    public void defaultSigningVersion() throws IOException {
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        signedNftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys);
        SignedNFTAttestation newSignedNftAtt = new SignedNFTAttestation(signedNftAttestation.getUnsignedAttestation(), signedNftAttestation.getSignature());
        assertArrayEquals(signedNftAttestation.getDerEncoding(), newSignedNftAtt.getDerEncoding());
        assertTrue(newSignedNftAtt.verify());
        assertTrue(newSignedNftAtt.checkValidity());
        SignedNFTAttestation otherConstructor = new SignedNFTAttestation(newSignedNftAtt.getDerEncoding(), attestorKeys.getPublic());
        assertArrayEquals(signedNftAttestation.getDerEncoding(), otherConstructor.getDerEncoding());
        assertTrue(otherConstructor.verify());
        assertTrue(otherConstructor.checkValidity());
    }

    @Test
    public void oldVersionSigning() throws IOException {
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        signedNftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys, 1);
        SignedNFTAttestation newSignedNftAtt = new SignedNFTAttestation(signedNftAttestation.getUnsignedAttestation(), signedNftAttestation.getSignature());
        assertArrayEquals(signedNftAttestation.getDerEncoding(), newSignedNftAtt.getDerEncoding());
        assertTrue(newSignedNftAtt.verify());
        assertTrue(newSignedNftAtt.checkValidity());
        SignedNFTAttestation otherConstructor = new SignedNFTAttestation(newSignedNftAtt.getDerEncoding(), attestorKeys.getPublic());
        assertArrayEquals(signedNftAttestation.getDerEncoding(), otherConstructor.getDerEncoding());
        assertTrue(otherConstructor.verify());
        assertTrue(otherConstructor.checkValidity());
    }

    @Test
    public void unknownVersion() {
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestation(nftAtt, subjectKeys, 42));
    }

    @Test
    public void unknownVersionOtherConstructor() {
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        Signature rawSig = new RawSignature(subjectKeys, nftAtt.getDerEncoding());
        assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestation(nftAtt, rawSig));
    }

    @Test
    public void badSignatureVersion() {
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        signedNftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys);
        assertThrows(IllegalArgumentException.class, ()-> signedNftAttestation.makeSignature(new byte[] {0x42}, 42));
    }

    @Test
    public void badSignatureVersionOtherVersion() {
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        signedNftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys);
        assertThrows(IllegalArgumentException.class, ()-> signedNftAttestation.makeSignature(subjectKeys, 42));
    }

    @Test
    public void signingVersion1Included() throws IOException {
        String urlEncodedSignedNftAtt = "MIICqTCCAlMwggIXMIIBxKADAgETAgEBMAkGByqGSM49BAIwGTEXMBUGA1UEAwwOYXR0ZXN0YXRpb24uaWQwIhgPMjAyMTExMDkxNjIwMThaGA85OTk5MTIzMTIyNTk1OVowOTE3MDUGCSsGAQQBgXoBOQwoaHR0cHM6Ly90d2l0dGVyLmNvbS96aGFuZ3dlaXd1IDIwNTUyMTY3NjCCATMwgewGByqGSM49AgEwgeACAQEwLAYHKoZIzj0BAQIhAP____________________________________7___wvMEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1LgCIQD____________________-uq7c5q9IoDu_0l6M0DZBQQIBAQNCAASVDHwL7SPDysXMMbu5qtm7VTI4eIJnCsKxzfB5mrDrx2TCZ_cE6P3aB5arg5ek0hAQJNJMTv_2lbOkF_LtDkjNMAkGByqGSM49BAIDQgD8Wu2eGeRW1GNFxOk5Srdn4E968ML7MUINj55zBqhuOhUWmosV5d4VsarkmpCmlwAXxvIpt7UcFP4cK8QuwH89GzA2MBkEFKVn9aFlVF-iY5u9p5mR8QXq34UiBAEZMBkEFKVn9aFlVF-iY5u9p5mR8QXq34UiBAEaAgEBMAkGByqGSM49BAIDQgCrpY0RQ3LNfJd6YgYEC-etEU_oJKUAA6WP0TRfZITeQVNNm21BOFQc-iiXs053UcSy1y29tbUPt1wp4VRU8Qu4Gw==";
        signedNftAttestation = new SignedNFTAttestation(URLUtility.decodeData(urlEncodedSignedNftAtt), attestorKeys.getPublic());
        SignedNFTAttestation newSignedNftAtt = new SignedNFTAttestation(signedNftAttestation.getUnsignedAttestation(), signedNftAttestation.getSignature());
        assertTrue(newSignedNftAtt.verify());
        assertTrue(newSignedNftAtt.checkValidity());
    }

    @Test
    public void badSignature() {
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        signedNftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys);
        Signature wrongSignature = new PersonalSignature(subjectKeys, "something wrong".getBytes(
            StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestation(nftAtt, wrongSignature));
    }

    @Test
    public void badSigningKey() {
        AsymmetricCipherKeyPair notAttestedKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        NFTAttestation nftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestation(nftAtt, notAttestedKeys));
    }

    @Test
    public void badNftAttestation() {
        Mockito.when(mockedNftAttestation.verify()).thenReturn(false);
        Mockito.when(mockedNftAttestation.getDerEncoding()).thenReturn(new byte[] {0x42});
        assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestation(mockedNftAttestation, subjectKeys));
    }

    @Test
    public void unverifiableSignedIdentifierAtt() {
        NFTAttestation realNftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        Mockito.when(mockedSignedIdentifierAtt.verify()).thenReturn(false);
        Mockito.when(mockedSignedIdentifierAtt.getDerEncoding()).thenReturn(realNftAtt.getDerEncoding());
        NFTAttestation nftAtt = new NFTAttestation(mockedSignedIdentifierAtt, nfts);
        assertThrows(IllegalArgumentException.class, ()-> new SignedNFTAttestation(nftAtt, subjectKeys));
    }

    @Test
    public void invalidSignedIdentifierAtt() throws Exception {
        NFTAttestation realNftAtt = new NFTAttestation(signedIdentifierAtt, nfts);
        IdentifierAttestation identifierAttestation =  new IdentifierAttestation("205521676", "https://twitter.com/zhangweiwu", subjectKeys.getPublic());
        Mockito.when(mockedSignedIdentifierAtt.verify()).thenReturn(true);
        Mockito.when(mockedSignedIdentifierAtt.checkValidity()).thenReturn(false);
        Mockito.when(mockedSignedIdentifierAtt.getDerEncoding()).thenReturn(realNftAtt.getDerEncoding());
        Mockito.when(mockedSignedIdentifierAtt.getUnsignedAttestation()).thenReturn(identifierAttestation);
        NFTAttestation nftAtt = new NFTAttestation(mockedSignedIdentifierAtt, nfts);
        signedNftAttestation = new SignedNFTAttestation(nftAtt, subjectKeys);
        assertTrue(signedNftAttestation.verify());
        assertFalse(signedNftAttestation.checkValidity());
    }
}
