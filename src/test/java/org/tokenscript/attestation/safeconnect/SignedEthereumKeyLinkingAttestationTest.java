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
import org.tokenscript.attestation.ERC721Token;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.core.SignatureUtility;

import java.io.InvalidObjectException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class SignedEthereumKeyLinkingAttestationTest {
    private static final X9ECParameters SUBTLE_CRYPTO_CURVE = SECNamedCurves.getByName("secp256r1"); // NIST P-256
    private static final byte[] context = new byte[]{0x00};
    private static final String address = "0x0102030405060708091011121314151617181920";
    private static final long defaultValidity = 60; //seconds
    private static final ERC721Token[] nfts = new ERC721Token[]{
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "25"),
            new ERC721Token("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "26")
    };
    private static AsymmetricCipherKeyPair subjectECKeys;
    private static AsymmetricCipherKeyPair subjectRSAKeys;
    private static AsymmetricCipherKeyPair wrongKey;
    private static AsymmetricCipherKeyPair issuerECKeys;
    private static AsymmetricCipherKeyPair issuerRSAKeys;
    private static SecureRandom rand;
    private static SignedNFTOwnershipAttestation nftOwnershipAtt;
    private static SignedEthereumAddressAttestation addressAttestation;

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rand.setSeed("seed".getBytes());
        subjectECKeys = SignatureUtility.constructECKeys(SUBTLE_CRYPTO_CURVE, rand);
        issuerECKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        nftOwnershipAtt = new SignedNFTOwnershipAttestation(context, subjectECKeys.getPublic(), nfts, defaultValidity, issuerECKeys);
        addressAttestation = new SignedEthereumAddressAttestation(context, subjectECKeys.getPublic(), address, defaultValidity, issuerECKeys);
        RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters subjectParam = new RSAKeyGenerationParameters(new BigInteger("3"), rand, 1024, 80);
        rsaGen.init(subjectParam);
        subjectRSAKeys = rsaGen.generateKeyPair();
        RSAKeyGenerationParameters issuerParam = new RSAKeyGenerationParameters(new BigInteger("65537"), rand, 2048, 80);
        rsaGen.init(issuerParam);
        issuerRSAKeys = rsaGen.generateKeyPair();
        Ed448KeyPairGenerator kpg = new Ed448KeyPairGenerator();
        kpg.init(new Ed448KeyGenerationParameters(rand));
        wrongKey = kpg.generateKeyPair();
    }

    // Write test material to be used in JS testing
    @Test
    public void writeTestMaterial() throws Exception {
        ImportExportHelper.produceTestMaterial(
                new SignedEthereumKeyLinkingAttestation(context, address, nftOwnershipAtt, subjectECKeys), "nft-subject-ec-issuer-ec");
        ImportExportHelper.produceTestMaterial(
                new SignedEthereumKeyLinkingAttestation(context, address, addressAttestation, subjectECKeys), "address-subject-ec-issuer-ec");
        ImportExportHelper.produceTestMaterial(
                new SignedEthereumKeyLinkingAttestation(context, address,
                        new SignedNFTOwnershipAttestation(null, subjectRSAKeys.getPublic(), nfts, defaultValidity, issuerECKeys),
                        subjectRSAKeys), "nft-subject-rsa-issuer-ec");
        ImportExportHelper.produceTestMaterial(
                new SignedEthereumKeyLinkingAttestation(context, address,
                        new SignedEthereumAddressAttestation(null, subjectECKeys.getPublic(), address, defaultValidity, issuerRSAKeys),
                        subjectECKeys), "address-subject-ec-issuer-rsa");

        ImportExportHelper.storeKey(issuerECKeys.getPublic(), "ec");
        ImportExportHelper.storeKey(issuerRSAKeys.getPublic(), "rsa");

        ObjectDecoder<SignedOwnershipAttestationInterface> internalDecoder;
        SignedEthereumKeyLinkingAttestation att;

        // Validate loading
        AsymmetricKeyParameter ecKey = ImportExportHelper.loadKey("ec");
        AsymmetricKeyParameter rsaKey = ImportExportHelper.loadKey("rsa");

        internalDecoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), ecKey);
        att = ImportExportHelper.loadTestMaterial(internalDecoder, "nft-subject-ec-issuer-ec");
        assertTrue(att.verify());
        assertTrue(att.checkValidity());

        internalDecoder = new SignedOwnershipAttestationDecoder(new EthereumAddressAttestationDecoder(), ecKey);
        att = ImportExportHelper.loadTestMaterial(internalDecoder, "address-subject-ec-issuer-ec");
        assertTrue(att.verify());
        assertTrue(att.checkValidity());

        internalDecoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), ecKey);
        att = ImportExportHelper.loadTestMaterial(internalDecoder, "nft-subject-rsa-issuer-ec");
        assertTrue(att.verify());
        assertTrue(att.checkValidity());

        internalDecoder = new SignedOwnershipAttestationDecoder(new EthereumAddressAttestationDecoder(), rsaKey);
        att = ImportExportHelper.loadTestMaterial(internalDecoder, "address-subject-ec-issuer-rsa");
        assertTrue(att.verify());
        assertTrue(att.checkValidity());
    }

    @Test
    public void sunshine() throws Exception {
        validateSunshine(context, address, nftOwnershipAtt, subjectECKeys);
        validateSunshine(context, address, addressAttestation, subjectECKeys);
        validateSunshine(null, address, nftOwnershipAtt, subjectECKeys);
        validateSunshine(context, address,
                new SignedNFTOwnershipAttestation(null, subjectRSAKeys.getPublic(), nfts, defaultValidity, issuerECKeys),
                subjectRSAKeys);
    }

    public void validateSunshine(byte[] context, String address, SignedOwnershipAttestationInterface internalAtt, AsymmetricCipherKeyPair signingKeys) throws Exception {
        SignedEthereumKeyLinkingAttestation att = new SignedEthereumKeyLinkingAttestation(context, address, internalAtt, signingKeys);
        assertTrue(att.checkValidity());
        assertTrue(att.verify());
        assertArrayEquals(context, att.getContext());
        assertEquals(address, att.getSubjectAddress());
        assertEquals(SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(signingKeys.getPublic()), SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(att.getVerificationKey()));
        assertArrayEquals(internalAtt.getDerEncoding(), att.getOwnershipAttestation().getDerEncoding());
    }

    @Test
    public void decodingTest() throws Exception {
        ObjectDecoder<SignedOwnershipAttestationInterface> nftOwnershipDecoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), issuerECKeys.getPublic());
        decodingAtt(context, address, defaultValidity, nftOwnershipAtt, subjectECKeys, nftOwnershipDecoder);
        decodingAtt(null, address, defaultValidity, nftOwnershipAtt, subjectECKeys, nftOwnershipDecoder);
        ObjectDecoder<SignedOwnershipAttestationInterface> addressOwnershipDecoder = new SignedOwnershipAttestationDecoder(new EthereumAddressAttestationDecoder(), issuerECKeys.getPublic());
        decodingAtt(context, address, defaultValidity, addressAttestation, subjectECKeys, addressOwnershipDecoder);
        ObjectDecoder<SignedOwnershipAttestationInterface> nftOwnershipSubjectRsaDecoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), issuerECKeys.getPublic());
        decodingAtt(context, address, defaultValidity,
                new SignedNFTOwnershipAttestation(null, subjectRSAKeys.getPublic(), nfts, defaultValidity, issuerECKeys),
                subjectRSAKeys, nftOwnershipSubjectRsaDecoder);
        ObjectDecoder<SignedOwnershipAttestationInterface> nftOwnershipIssuerRsaDecoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), issuerRSAKeys.getPublic());
        decodingAtt(context, address, defaultValidity,
                new SignedNFTOwnershipAttestation(null, subjectECKeys.getPublic(), nfts, defaultValidity, issuerRSAKeys),
                subjectECKeys, nftOwnershipIssuerRsaDecoder);
    }

    public void decodingAtt(byte[] context, String address, long validity, SignedOwnershipAttestationInterface internalAtt, AsymmetricCipherKeyPair signingKeys, ObjectDecoder<SignedOwnershipAttestationInterface> decoder) throws Exception {
        SignedEthereumKeyLinkingAttestation att = new SignedEthereumKeyLinkingAttestation(context, address, validity, internalAtt, signingKeys);
        SignedEthereumKeyLinkingAttestationDecoder outerDecoder = new SignedEthereumKeyLinkingAttestationDecoder(decoder);
        SignedEthereumKeyLinkingAttestation decodedAtt = outerDecoder.decode(att.getDerEncoding());
        assertTrue(decodedAtt.checkValidity());
        assertTrue(decodedAtt.verify());
        assertArrayEquals(context, decodedAtt.getContext());
        assertEquals(address, decodedAtt.getSubjectAddress());
        assertEquals(SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(signingKeys.getPublic()), SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(att.getVerificationKey()));
        assertArrayEquals(internalAtt.getDerEncoding(), att.getOwnershipAttestation().getDerEncoding());
        assertEquals(att.getNotBefore(), decodedAtt.getNotBefore());
        assertEquals(att.getNotAfter(), decodedAtt.getNotAfter());
        assertArrayEquals(att.getDerEncoding(), decodedAtt.getDerEncoding());
    }

    @Test
    public void incorrectValidity() {
        assertThrows(IllegalArgumentException.class, () -> new SignedEthereumKeyLinkingAttestation(context, address, -1, nftOwnershipAtt, subjectECKeys));
    }

    @Test
    public void badSig() {
        SignedEthereumKeyLinkingAttestation validAtt = new SignedEthereumKeyLinkingAttestation(context, address, nftOwnershipAtt, subjectECKeys);
        // wrong address so sig verification should fail
        assertThrows(IllegalArgumentException.class, () -> new SignedEthereumKeyLinkingAttestation(validAtt.getContext(), "0x1111111405060708091011121314151617181920", validAtt.getNotBefore(), validAtt.getNotAfter(), validAtt.getOwnershipAttestation(), validAtt.getSignature()));
    }

    @Test
    public void wrongAlgorithm() {
        ObjectDecoder<SignedOwnershipAttestationInterface> nftOwnershipDecoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), issuerECKeys.getPublic());
        SignedEthereumKeyLinkingAttestationDecoder decoder = new SignedEthereumKeyLinkingAttestationDecoder(nftOwnershipDecoder);
        assertThrows(IllegalArgumentException.class, () -> decoder.checkAlgorithm(SignatureUtility.RSASSA_PSS_ALG, issuerECKeys.getPublic()));
    }

    @Test
    public void incorrectUserHoldingKey() {
        AsymmetricCipherKeyPair otherKeys = SignatureUtility.constructECKeys(SUBTLE_CRYPTO_CURVE, rand);
        assertThrows(IllegalArgumentException.class, () -> new SignedEthereumKeyLinkingAttestation(context, address, nftOwnershipAtt, otherKeys));
    }

    @Test
    public void expiredInternalNFTAtt() throws Exception {
//        SignedNFTOwnershipAttestation expiredAtt = new SignedNFTOwnershipAttestation(context, subjectECKeys.getPublic(), nfts, 0, issuerECKeys);
//        String expiredEncoding = Base64.toBase64String(expiredAtt.getDerEncoding());
        String expiredAttEnc = "MIIB2zCCAYAwggEzMIHsBgcqhkjOPQIBMIHgAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP///////////////zBEBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsEQQRrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1AiEA/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQEDQgAEyrEXZr3LA5qZqEDhXhnVo6uGO3ON+9ZloychC03WvbTYntgoRp5WHqEo1LvUUK070UUsXXmRXdvaFuiUr/U3njA2MBkEFKVn9aFlVF+iY5u9p5mR8QXq34UiBAEZMBkEFKVn9aFlVF+iY5u9p5mR8QXq34UiBAEaMAwCBGK+2/ICBGK+2/IEAQAwCgYIKoZIzj0EAwIDSQAwRgIhALNbv1rosHZZgMcU4A21vlMC9KjT7k7RJkgqzCXXEwlxAiEA/KUEFLMZV1tACPRh0tf0wpVUxP6gCSljYvVhuhBxrig=";
        ObjectDecoder<SignedOwnershipAttestationInterface> nftOwnershipDecoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), issuerECKeys.getPublic());
        SignedNFTOwnershipAttestation expiredAtt = (SignedNFTOwnershipAttestation) nftOwnershipDecoder.decode(Base64.decode(expiredAttEnc));
        assertTrue(expiredAtt.verify());
        assertFalse(expiredAtt.checkValidity());
        SignedEthereumKeyLinkingAttestation linkingAttestation = new SignedEthereumKeyLinkingAttestation(context, address, expiredAtt, subjectECKeys);
        assertTrue(linkingAttestation.verify());
        assertFalse(linkingAttestation.checkValidity());
    }

    @Test
    public void expiredInternalAddressAtt() throws Exception {
//        SignedEthereumAddressAttestation expiredAtt1 = new SignedEthereumAddressAttestation(context, subjectECKeys.getPublic(), address, 0, issuerECKeys);
//        String expiredEncoding = Base64.toBase64String(expiredAtt1.getDerEncoding());
        String expiredAttEnc = "MIIBtzCCAV4wggEzMIHsBgcqhkjOPQIBMIHgAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP///////////////zBEBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsEQQRrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1AiEA/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQEDQgAEyrEXZr3LA5qZqEDhXhnVo6uGO3ON+9ZloychC03WvbTYntgoRp5WHqEo1LvUUK070UUsXXmRXdvaFuiUr/U3ngQUAQIDBAUGBwgJEBESExQVFhcYGSAwDAIEYr7elgIEYr7elgQBADAKBggqhkjOPQQDAgNHADBEAiBTpmN2jtZkVPZNCPdHJcYScvQAKDGDuBHBX54J1PZhhgIgDLY546mGu6IjFPGs49U14igcboPWPSmyWPR7v2l8YuM=";
        ObjectDecoder<SignedOwnershipAttestationInterface> addressOwnershipDecoder = new SignedOwnershipAttestationDecoder(new EthereumAddressAttestationDecoder(), issuerECKeys.getPublic());
        SignedEthereumAddressAttestation expiredAtt = (SignedEthereumAddressAttestation) addressOwnershipDecoder.decode(Base64.decode(expiredAttEnc));
        assertTrue(expiredAtt.verify());
        assertFalse(expiredAtt.checkValidity());
        SignedEthereumKeyLinkingAttestation linkingAttestation = new SignedEthereumKeyLinkingAttestation(context, address, expiredAtt, subjectECKeys);
        assertTrue(linkingAttestation.verify());
        assertFalse(linkingAttestation.checkValidity());
    }

    @Test
    public void badSigAtt() throws Exception {
//        SignedEthereumKeyLinkingAttestation att = new SignedEthereumKeyLinkingAttestation(context, address, nftOwnershipAtt, subjectECKeys);
//        String attEnc = Base64.toBase64String(att.getDerEncoding());
        String badAttEnc = "MIICYDCCAgYEFAECAwQFBgcICRAREhMUFRYXGBkgMIIB2zCCAYAwggEzMIHsBgcqhkjOPQIBMIHgAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP///////////////zBEBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsEQQRrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1AiEA/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQEDQgAEyrEXZr3LA5qZqEDhXhnVo6uGO3ON+9ZloychC03WvbTYntgoRp5WHqEo1LvUUK070UUsXXmRXdvaFuiUr/U3njA2MBkEFKVn9aFlVF+iY5u9p5mR8QXq34UiBAEZMBkEFKVn9aFlVF+iY5u9p5mR8QXq34UiBAEaMAwCBGK+4XACBGK+4awEAQAwCgYIKoZIzj0EAwIDSQAwRgIhALx6DOJwBzNX1VFXDqManKn41p6lV2PnI38hEMnX3KTsAiEAq/BUQCu25lPgM7bP+4wLjy4FaIyGvcXyg2IjoUPNkxEwDAIEYr7hcQIEYr7vgQQBADAKBggqhkjOPQQDAgNIADBFAiA1XfC2a2dHaMYKWUBePqogpdzlhaeZotwT58IC+PlwngIhANoy+i8TpyiOpoXbsKjnA2iCft1O/fM/bmi0VIr20Vku";
        ObjectDecoder<SignedOwnershipAttestationInterface> nftOwnershipDecoder = new SignedOwnershipAttestationDecoder(new NFTOwnershipAttestationDecoder(), issuerECKeys.getPublic());
        SignedEthereumKeyLinkingAttestationDecoder outerDecoder = new SignedEthereumKeyLinkingAttestationDecoder(nftOwnershipDecoder);
        assertThrows(IllegalArgumentException.class, () -> outerDecoder.decode(Base64.decode(badAttEnc)));
    }


    @Test
    public void tooOld() {
        // The attestation is not yet valid
        TestOwnerShipAttestation att = new TestOwnerShipAttestation(1000, 1, 999);
        assertFalse(att.checkValidity());
    }

    @Test
    public void tooYoung() {
        // The attestation is not yet valid
        TestOwnerShipAttestation att = new TestOwnerShipAttestation(1000, 1001, 2000);
        assertFalse(att.checkValidity());
    }


    class TestOwnerShipAttestation extends AbstractSignedOwnershipAttestation {
        private Date currentTime = new Date(0);
        private Date notBefore = new Date(0);
        private Date notAfter = new Date(0);

        public TestOwnerShipAttestation(long currentTime, long notBefore, long notAfter) {
            this.currentTime = new Date(currentTime);
            this.notBefore = new Date(notBefore);
            this.notAfter = new Date(notAfter);
        }

        @Override
        public Date getNotBefore() {
            return notBefore;
        }

        @Override
        public Date getNotAfter() {
            return notAfter;
        }

        @Override
        protected AsymmetricKeyParameter getVerificationKey() {
            return null;
        }

        @Override
        protected Date getCurrentTime() {
            return currentTime;
        }

        @Override
        protected byte[] getUnsignedEncoding() {
            return new byte[0];
        }

        @Override
        protected byte[] getSignature() {
            return new byte[0];
        }

        @Override
        public byte[] getDerEncoding() throws InvalidObjectException {
            return new byte[0];
        }

        @Override
        public boolean verify() {
            return false;
        }
    }
}
