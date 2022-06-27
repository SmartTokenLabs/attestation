package org.tokenscript.attestation.safeconnect;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.ERC721Token;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.core.SignatureUtility;

import java.math.BigInteger;
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

    @Test
    public void sunshine() throws Exception {
        validateSunshine(context, address, defaultValidity, nftOwnershipAtt, subjectECKeys);
        validateSunshine(context, address, defaultValidity, addressAttestation, subjectECKeys);
        validateSunshine(null, address, defaultValidity, nftOwnershipAtt, subjectECKeys);
        validateSunshine(context, address, defaultValidity,
                new SignedNFTOwnershipAttestation(null, subjectRSAKeys.getPublic(), nfts, defaultValidity, issuerECKeys),
                subjectRSAKeys);
    }

    public void validateSunshine(byte[] context, String address, long validity, SignedOwnershipAttestationInterface internalAtt, AsymmetricCipherKeyPair signingKeys) throws Exception {
        SignedEthereumKeyLinkingAttestation att = new SignedEthereumKeyLinkingAttestation(context, address, validity, internalAtt, signingKeys);
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
}
