package org.tokenscript.attestation.safeconnect;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.tokenscript.attestation.ERC721Token;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.core.SignatureUtility;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

public class SignedOwnershipAttestationTest {
    // todo make general test setup fixture and use groovy
    private static final X9ECParameters SUBTLE_CRYPTO_CURVE = SECNamedCurves.getByName("secp256r1"); // NIST P-256
    private static final ERC721Token[] nfts = new ERC721Token[]{
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "25"),
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "26")
    };
    private static final ERC721Token[] nftsWOTokenId = new ERC721Token[]{
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522")
    };
    private static final ERC721Token[] nftsWChainId = new ERC721Token[]{
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", 42L),
            new ERC721Token("0xa567f5A165545Faa639bBdA79991F105EADF8522", 1L)
    };
    private static final ERC721Token[] nftsEmpty = new ERC721Token[0];
    private static final String address = "0x0102030405060708091011121314151617181920";
    private static AsymmetricCipherKeyPair issuerKeys;
    //    private static AsymmetricCipherKeyPair issuerRSAKeys;
    private static SecureRandom rand;
    private static final byte[] context = new byte[]{0x00};
    private static final long defaultValidity = 60; //seconds
    private static AsymmetricCipherKeyPair subjectECKeys;
    private static AsymmetricCipherKeyPair subjectRSAKeys;
    private static AsymmetricCipherKeyPair wrongKey;


    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rand.setSeed("seed".getBytes());
        subjectECKeys = SignatureUtility.constructECKeys(SUBTLE_CRYPTO_CURVE, rand);
        issuerKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters subjectParam = new RSAKeyGenerationParameters(new BigInteger("3"), rand, 1024, 80);
        rsaGen.init(subjectParam);
        subjectRSAKeys = rsaGen.generateKeyPair();
        RSAKeyGenerationParameters issuerParam = new RSAKeyGenerationParameters(new BigInteger("65537"), rand, 2048, 80);
        rsaGen.init(issuerParam);
//        issuerRSAKeys = rsaGen.generateKeyPair();
        Ed448KeyPairGenerator kpg = new Ed448KeyPairGenerator();
        kpg.init(new Ed448KeyGenerationParameters(rand));
        wrongKey = kpg.generateKeyPair();
    }

    @Test
    void nftOwnershipTest() {
        sunshineNFTOwnership(context, subjectECKeys.getPublic(), nfts, issuerKeys);
        sunshineNFTOwnership(context, subjectECKeys.getPublic(), nftsWOTokenId, issuerKeys);
        sunshineNFTOwnership(context, subjectECKeys.getPublic(), nftsEmpty, issuerKeys);
        sunshineNFTOwnership(context, subjectECKeys.getPublic(), nftsWChainId, issuerKeys);
        sunshineNFTOwnership(null, subjectECKeys.getPublic(), nfts, issuerKeys);
        sunshineNFTOwnership(context, subjectECKeys.getPublic(), nfts, issuerKeys);
        sunshineNFTOwnership(context, subjectRSAKeys.getPublic(), nfts, issuerKeys);
//        sunshineNFTOwnership(context, subjectRSAKeys.getPublic(), nfts, issuerRSAKeys);
//        sunshineNFTOwnership(context, subjectECKeys.getPublic(), nfts, issuerRSAKeys);
    }

    void sunshineNFTOwnership(byte[] context, AsymmetricKeyParameter subjectKey, ERC721Token[] tokens, AsymmetricCipherKeyPair signingKeys) {
        SignedNFTOwnershipAttestation att = new SignedNFTOwnershipAttestation(context, subjectKey, tokens, signingKeys);
        assertTrue(att.checkValidity());
        assertTrue(att.verify());
        assertEquals(context, att.getContext());
        assertEquals(SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(subjectKey), SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(att.getSubtlePublicKey()));
        assertEquals(SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(signingKeys.getPublic()), SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(att.getVerificationKey()));
        assertArrayEquals(tokens, att.getTokens());
    }

    @Test
    void addressOwnershipTest() {
        sunshineAddressOwnership(context, subjectECKeys.getPublic(), address, issuerKeys);
        sunshineAddressOwnership(null, subjectECKeys.getPublic(), address, issuerKeys);
        sunshineAddressOwnership(context, subjectECKeys.getPublic(), address, issuerKeys);
        sunshineAddressOwnership(context, subjectRSAKeys.getPublic(), address, issuerKeys);
//        sunshineAddressOwnership(context, subjectRSAKeys.getPublic(), address, issuerRSAKeys);
//        sunshineAddressOwnership(context, subjectECKeys.getPublic(), address, issuerRSAKeys);
    }

    void sunshineAddressOwnership(byte[] context, AsymmetricKeyParameter subjectKey, String address, AsymmetricCipherKeyPair signingKeys) {
        SignedEthereumAddressAttestation att = new SignedEthereumAddressAttestation(context, subjectKey, address, signingKeys);
        assertTrue(att.checkValidity());
        assertTrue(att.verify());
        assertEquals(context, att.getContext());
        assertEquals(SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(subjectKey), SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(att.getSubtlePublicKey()));
        assertEquals(SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(signingKeys.getPublic()), SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(att.getVerificationKey()));
        assertEquals(address, att.getSubjectAddress());
    }

    @Test
    void nftOwnershipDecodingTest() throws Exception {
        decodingNFTOwnership(context, subjectECKeys.getPublic(), nfts, issuerKeys);
        decodingNFTOwnership(context, subjectECKeys.getPublic(), nftsWOTokenId, issuerKeys);
        decodingNFTOwnership(context, subjectECKeys.getPublic(), nftsEmpty, issuerKeys);
        decodingNFTOwnership(context, subjectECKeys.getPublic(), nftsWChainId, issuerKeys);
        decodingNFTOwnership(null, subjectECKeys.getPublic(), nfts, issuerKeys);
        decodingNFTOwnership(context, subjectECKeys.getPublic(), nfts, issuerKeys);
        decodingNFTOwnership(context, subjectRSAKeys.getPublic(), nfts, issuerKeys);
//        decodingNFTOwnership(context, subjectRSAKeys.getPublic(), nfts, issuerRSAKeys);
//        decodingNFTOwnership(context, subjectECKeys.getPublic(), nfts, issuerRSAKeys);
    }

    void decodingNFTOwnership(byte[] context, AsymmetricKeyParameter subjectKey, ERC721Token[] tokens, AsymmetricCipherKeyPair signingKeys) throws Exception {
        SignedNFTOwnershipAttestation att = new SignedNFTOwnershipAttestation(context, subjectKey, tokens, signingKeys);
        SignedOwnershipAttestationDecoder decoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), signingKeys.getPublic());
        SignedNFTOwnershipAttestation decodedAtt = (SignedNFTOwnershipAttestation) decoder.decode(att.getDerEncoding());
        assertTrue(decodedAtt.checkValidity());
        assertTrue(decodedAtt.verify());
        assertArrayEquals(context, decodedAtt.getContext());
        assertEquals(SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(subjectKey), SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(decodedAtt.getSubtlePublicKey()));
        assertEquals(SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(signingKeys.getPublic()), SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(decodedAtt.getVerificationKey()));
        for (int i = 0; i < tokens.length; i++) {
            assertArrayEquals(tokens[i].getDerEncoding(), decodedAtt.getTokens()[i].getDerEncoding());
        }
        assertEquals(tokens.length, decodedAtt.getTokens().length);
        assertEquals(att.getNotBefore(), decodedAtt.getNotBefore());
        assertEquals(att.getNotAfter(), decodedAtt.getNotAfter());
        assertArrayEquals(att.getDerEncoding(), decodedAtt.getDerEncoding());
    }

    @Test
    void addressOwnershipDecodingTest() throws Exception {
        decodingAddressOwnership(context, subjectECKeys.getPublic(), address, defaultValidity, issuerKeys);
        decodingAddressOwnership(null, subjectECKeys.getPublic(), address, defaultValidity, issuerKeys);
        decodingAddressOwnership(context, subjectECKeys.getPublic(), address, defaultValidity, issuerKeys);
        decodingAddressOwnership(context, subjectRSAKeys.getPublic(), address, defaultValidity, issuerKeys);
//        decodingAddressOwnership(context, subjectRSAKeys.getPublic(), address, defaultValidity, issuerRSAKeys);
//        decodingAddressOwnership(context, subjectECKeys.getPublic(), address, defaultValidity, issuerRSAKeys);
    }

    void decodingAddressOwnership(byte[] context, AsymmetricKeyParameter subjectKey, String address, long validity, AsymmetricCipherKeyPair signingKeys) throws Exception {
        SignedEthereumAddressAttestation att = new SignedEthereumAddressAttestation(context, subjectKey, address, validity, signingKeys);
        SignedOwnershipAttestationDecoder decoder = new SignedOwnershipAttestationDecoder(new EthereumAddressAttestationDecoder(), signingKeys.getPublic());
        SignedEthereumAddressAttestation decodedAtt = (SignedEthereumAddressAttestation) decoder.decode(att.getDerEncoding());
        assertTrue(decodedAtt.checkValidity());
        assertTrue(decodedAtt.verify());
        assertArrayEquals(context, decodedAtt.getContext());
        assertEquals(SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(subjectKey), SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(decodedAtt.getSubtlePublicKey()));
        assertEquals(SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(signingKeys.getPublic()), SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(decodedAtt.getVerificationKey()));
        assertEquals(att.getNotBefore(), decodedAtt.getNotBefore());
        assertEquals(att.getNotAfter(), decodedAtt.getNotAfter());
        assertEquals(att.getSubjectAddress(), address);
        assertArrayEquals(att.getDerEncoding(), decodedAtt.getDerEncoding());
    }

    @Test
    void illegalArgumentNFTOwnershipTest() throws Exception {
        illegalArgumentNFTOwnership(context, subjectECKeys.getPublic(), nfts, -1, issuerKeys);
        illegalArgumentNFTOwnership(context, subjectECKeys.getPublic(), nfts, defaultValidity, wrongKey);
//        illegalArgumentNFTOwnership(context, wrongKey.getPublic(), nfts, defaultValidity, issuerECKeys);
        illegalArgumentNFTOwnership(context, subjectECKeys.getPublic(), null, defaultValidity, issuerKeys);
        illegalArgumentNFTOwnership(context, null, nfts, defaultValidity, issuerKeys);
        illegalArgumentNFTOwnership(context, subjectECKeys.getPublic(), nfts, defaultValidity, null);
    }

    void illegalArgumentNFTOwnership(byte[] context, AsymmetricKeyParameter subjectKey, ERC721Token[] tokens, long validity, AsymmetricCipherKeyPair signingKeys) {
        assertThrows(IllegalArgumentException.class, () -> new SignedNFTOwnershipAttestation(context, subjectKey, tokens, validity, signingKeys));
    }

    @Test
    void illegalArgumentAddressOwnershipTest() throws Exception {
        illegalArgumentAddressOwnership(context, subjectECKeys.getPublic(), address, -1, issuerKeys);
        illegalArgumentAddressOwnership(context, subjectECKeys.getPublic(), address, defaultValidity, wrongKey);
//        illegalArgumentAddressOwnership(context, kpg.generateKeyPair().getPublic(), address, defaultValidity, issuerECKeys);
        illegalArgumentAddressOwnership(context, subjectECKeys.getPublic(), null, defaultValidity, issuerKeys);
        illegalArgumentAddressOwnership(context, null, address, defaultValidity, issuerKeys);
        illegalArgumentAddressOwnership(context, subjectECKeys.getPublic(), address, defaultValidity, null);
        illegalArgumentAddressOwnership(context, subjectECKeys.getPublic(), "0x12345678910", defaultValidity, issuerKeys);
    }

    void illegalArgumentAddressOwnership(byte[] context, AsymmetricKeyParameter subjectKey, String address, long validity, AsymmetricCipherKeyPair signingKeys) {
        assertThrows(IllegalArgumentException.class, () -> new SignedEthereumAddressAttestation(context, subjectKey, address, validity, signingKeys));
    }

    @Test
    void wrongVerifierKeyAddressAtt() {
        SignedEthereumAddressAttestation att = new SignedEthereumAddressAttestation(context, subjectECKeys.getPublic(), address, defaultValidity, issuerKeys);
        SignedOwnershipAttestationDecoder decoder = new SignedOwnershipAttestationDecoder(new EthereumAddressAttestationDecoder(), wrongKey.getPublic());
        assertThrows(IllegalArgumentException.class, () -> decoder.decode(att.getDerEncoding()));
    }

    @Test
    void wrongVerifierKeyNFTAtt() {
        SignedNFTOwnershipAttestation att = new SignedNFTOwnershipAttestation(context, subjectECKeys.getPublic(), nfts, defaultValidity, issuerKeys);
        SignedOwnershipAttestationDecoder decoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), wrongKey.getPublic());
        assertThrows(IllegalArgumentException.class, () -> decoder.decode(att.getDerEncoding()));
    }

//    @Test
//    public void unexpectedKeyFormatAddressAtt() {
//        SignedEthereumAddressAttestation att = new SignedEthereumAddressAttestation(context, subjectECKeys.getPublic(), address, defaultValidity, issuerKeys);
//        SignedOwnershipAttestationDecoder decoder = new SignedOwnershipAttestationDecoder(new EthereumAddressAttestationDecoder(), issuerRSAKeys.getPublic());
//        assertThrows(IllegalArgumentException.class, () -> decoder.decode(att.getDerEncoding()));
//    }
//
//    @Test
//    public void unexpectedKeyFormatNFTAtt() {
//        SignedNFTOwnershipAttestation att = new SignedNFTOwnershipAttestation(context, subjectECKeys.getPublic(), nfts, defaultValidity, issuerKeys);
//        SignedOwnershipAttestationDecoder decoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), issuerRSAKeys.getPublic());
//        assertThrows(IllegalArgumentException.class, () -> decoder.decode(att.getDerEncoding()));
//    }

    @Test
    void nftOwnershipBadOtherConstructor() {
        SignedNFTOwnershipAttestation att = new SignedNFTOwnershipAttestation(context, subjectECKeys.getPublic(), nfts, defaultValidity, issuerKeys);
        assertThrows(IllegalArgumentException.class, () -> new SignedNFTOwnershipAttestation(att.getContext(), wrongKey.getPublic(), att.getTokens(), att.getNotBefore(), att.getNotAfter(), att.getSignature(), att.getVerificationKey()));
        assertThrows(IllegalArgumentException.class, () -> new SignedNFTOwnershipAttestation(att.getContext(), att.getSubtlePublicKey(), att.getTokens(), att.getNotBefore(), att.getNotAfter(), att.getSignature(), wrongKey.getPublic()));
        assertThrows(IllegalArgumentException.class, () -> new SignedNFTOwnershipAttestation(att.getContext(), att.getSubtlePublicKey(), att.getTokens(), att.getNotBefore(), att.getNotAfter(), new byte[65], att.getVerificationKey()));
    }

    @Test
    void addressOwnershipBadOtherConstructor() {
        SignedEthereumAddressAttestation att = new SignedEthereumAddressAttestation(context, subjectECKeys.getPublic(), address, defaultValidity, issuerKeys);
        assertThrows(IllegalArgumentException.class, () -> new SignedEthereumAddressAttestation(att.getContext(), wrongKey.getPublic(), att.getSubjectAddress(), att.getNotBefore(), att.getNotAfter(), att.getSignature(), att.getVerificationKey()));
        assertThrows(IllegalArgumentException.class, () -> new SignedEthereumAddressAttestation(att.getContext(), att.getSubtlePublicKey(), att.getSubjectAddress(), att.getNotBefore(), att.getNotAfter(), att.getSignature(), wrongKey.getPublic()));
        assertThrows(IllegalArgumentException.class, () -> new SignedEthereumAddressAttestation(att.getContext(), att.getSubtlePublicKey(), att.getSubjectAddress(), att.getNotBefore(), att.getNotAfter(), new byte[65], att.getVerificationKey()));
    }

    @Test
    void badAddress() {
        SignedEthereumAddressAttestation att = new SignedEthereumAddressAttestation(context, subjectECKeys.getPublic(), address + "00", defaultValidity, issuerKeys);
        assertFalse(att.checkValidity());
    }

    @Test
    void badTokenMockito() {
        try (MockedConstruction<NFTOwnershipAttestation> mocked = mockConstruction(NFTOwnershipAttestation.class)) {
            NFTOwnershipAttestation mockedConstructorNft = new NFTOwnershipAttestation(null, null, null, null, null);
            when(mockedConstructorNft.getTokens()).thenReturn(new ERC721Token[]{new ERC721Token("not an address")});
            assertFalse(mockedConstructorNft.checkValidity());
        }
    }

    @Test
    void badToken() {
        NFTOwnershipAttestation att = new TestNFTOwnershipAttestation(new ERC721Token[]{new ERC721Token("not an address")});
        assertFalse(att.checkValidity());
    }

    @Test
    void badSigAtt() {
        String badAttEnc = "MIIB2zCCAYAwggEzMIHsBgcqhkjOPQIBMIHgAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP///////////////zBEBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsEQQRrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1AiEA/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQEDQgAEyrEXZr3LA5qZqEDhXhnVo6uGO3ON+9ZloychC03WvbTYntgoRp5WHqEo1LvUUK070UUsXXmRXdvaFuiUr/U3njA2MBkEFKVn9aFlVF+iY5u9p5mR8QXq34UiBAEZMBkEFKVn9aFlVF+iY5u9p5mR8QXq34UiBAEaMAwCBGK+2/ICBGK+2/IEAQAwCgYIKoZIzj0EAwIDSQAwRgIhALNbv1rosHZZgMcU4A21vlMC9KjT7k7RJkgqzCXXEwlxAiEA/KUEFLMZV1tACPRh0tf0wpVUxP7gCSljYvVhuhBxrig=";
        ObjectDecoder<SignedOwnershipAttestationInterface> nftOwnershipDecoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), issuerKeys.getPublic());
        assertThrows(IllegalArgumentException.class, () -> nftOwnershipDecoder.decode(Base64.decode(badAttEnc)));
    }

    class TestNFTOwnershipAttestation extends NFTOwnershipAttestation {
        public TestNFTOwnershipAttestation(ERC721Token[] tokens) {
            super(context, tokens, new Date(), new Date(), subjectECKeys.getPublic());
        }
    }

}
