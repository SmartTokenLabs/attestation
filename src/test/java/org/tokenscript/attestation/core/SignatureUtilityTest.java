package org.tokenscript.attestation.core;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.tokenscript.attestation.core.SignatureUtility.*;

public class SignatureUtilityTest {
  private static final X9ECParameters SECP364R1 = SECNamedCurves.getByName("secp384r1");
  private AsymmetricCipherKeyPair largeKeys;
  private AsymmetricCipherKeyPair userKeys;
  private SecureRandom rand;

  @BeforeEach
  public void setupCrypto() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());
    largeKeys = SignatureUtility.constructECKeys(SECP364R1, rand);
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

  // Note that secp256k1 is not accepted by default in java due to security reasons, hence only the large keys are validated here
  @Test
  public void testKeyConversion() throws Exception {
    byte[] message = "test".getBytes(StandardCharsets.UTF_8);
    byte[] digest = AttestationCrypto.hashWithSHA256(message);
    byte[] bcSignature = SignatureUtility.signHashedRandomized(digest, largeKeys.getPrivate());

    ECPrivateKey javaPriv = (ECPrivateKey) SignatureUtility.convertPrivateBouncyCastleKeyToJavaKey(largeKeys.getPrivate());
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(javaPriv);
    signer.update(message);
    byte[] javaSignature = signer.sign();

    ECPublicKey javaPub = (ECPublicKey) SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(largeKeys.getPublic());
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(javaPub);
    verifier.update(message);
    assertTrue(verifier.verify(javaSignature));

    verifier.initVerify(javaPub);
    verifier.update(message);
    assertTrue(verifier.verify(bcSignature));

    assertTrue(SignatureUtility.verifyHashed(digest, javaSignature, largeKeys.getPublic()));
    assertTrue(SignatureUtility.verifyHashed(digest, bcSignature, largeKeys.getPublic()));
  }

  @Test
  public void signDeterministic() throws Exception  {
    testSignDeterministic(userKeys);
    testSignDeterministic(largeKeys);
  }

  public void testSignDeterministic(AsymmetricCipherKeyPair keys) throws Exception  {
    byte[] message = new byte[515];
    message[0] = 42;
    message[514] = 13;

    byte[] signature = SignatureUtility.signDeterministicSHA256(message, keys.getPrivate());
    assertTrue(SignatureUtility.verifySHA256(message, signature, keys.getPublic()));
  }

  @Test
  public void signRandomized() throws Exception {
    testSignRandomized(largeKeys);
    testSignRandomized(userKeys);
  }

  public void testSignRandomized(AsymmetricCipherKeyPair keys) throws Exception {
    for (int i = 0; i < 50; i++) {
      byte[] message = new byte[256];
      message[0] = 0x42;
      message[255] = (byte) i;

      byte[] signature = SignatureUtility.signHashedRandomized(message, keys.getPrivate());
      assertTrue(SignatureUtility.verifyHashed(message, signature, keys.getPublic()));
    }
  }

  @Test
  public void testEthereumSigning() {
    byte[] message = new byte[515];
    message[0] = 43;
    message[514] = 15;
    byte[] signature = SignatureUtility.signPersonalMsgWithEthereum(message, userKeys.getPrivate());
    assertTrue(SignatureUtility.verifyPersonalEthereumSignature(message, signature, userKeys.getPublic()));
  }

  @Test
  public void testEthereumSigningNewChain() {
    byte[] message = new byte[515];
    message[0] = 41;
    message[514] = 45;
    byte[] signature = SignatureUtility.signPersonalMsgWithEthereum(message, 2, userKeys.getPrivate());
    assertTrue(SignatureUtility.verifyPersonalEthereumSignature(message, signature,
        SignatureUtility.addressFromKey(userKeys.getPublic()), 2));
  }

  @Test
  public void testEthereumSigningAgainstReference() {
    for (int i = 0; i < 50; i++) {
      // We make an extra long message and ensure that both the first and last bytes are not 0
      byte[] message = new byte[515];
      message[0] = 0x42;
      message[514] = (byte) i;

      BigInteger[] ourSig = SignatureUtility
              .computeInternalSignature(AttestationCrypto.hashWithKeccak(message), (ECPrivateKeyParameters) userKeys.getPrivate());
      BigInteger[] refSig = signDeterministic(message, userKeys.getPrivate());
      // We need to adjust the s part of the signature if it happens to be
      // less than N/2+1 since these are the only valid Ethereum signatures.
      if (refSig[1].compareTo(SECP256K1_DOMAIN.getN().shiftRight(1)) > 0) {
        refSig[1] = SECP256K1_DOMAIN.getN().subtract(refSig[1]);
      }
      assertEquals(refSig[0], ourSig[0]);
      assertEquals(refSig[1], ourSig[1]);
    }
  }

  @Test
  public void addressRecovery() {
    String address = SignatureUtility.addressFromKey(userKeys.getPublic());
    assertTrue(SignatureUtility.verifyKeyAgainstAddress(userKeys.getPublic(), address));
    assertFalse(SignatureUtility.verifyKeyAgainstAddress(userKeys.getPublic(), address+"00"));
    assertFalse(SignatureUtility.verifyKeyAgainstAddress(userKeys.getPublic(), "0"+address));
    byte[] addressBytes = address.getBytes();
    addressBytes[5] ^= 0x01;
    assertFalse(SignatureUtility.verifyKeyAgainstAddress(userKeys.getPublic(), new String(addressBytes)));
  }

  @Test
  public void recoverPublicKey() {
    byte[] message = new byte[] {0x42};
    byte[] testSignature = SignatureUtility.signWithEthereum(message, userKeys.getPrivate());
    String address = SignatureUtility.addressFromKey(userKeys.getPublic());
    AsymmetricKeyParameter key = SignatureUtility.recoverEthPublicKeyFromSignature(message, testSignature);
    assertEquals(address, SignatureUtility.addressFromKey(key));
  }

  @Test
  public void personalSigning() {
    String message = "hello world";
    byte[] personalSignature = SignatureUtility.signPersonalMsgWithEthereum(message.getBytes(
        StandardCharsets.UTF_8), userKeys.getPrivate());
    assertTrue(SignatureUtility.verifyPersonalEthereumSignature(message.getBytes(StandardCharsets.UTF_8),
        personalSignature, userKeys.getPublic()));
    // A personal signature does not verify as a normal signature
    assertFalse(SignatureUtility.verifyEthereumSignature(message.getBytes(StandardCharsets.UTF_8),
        personalSignature, userKeys.getPublic()));
    byte[] normalSignature = SignatureUtility.signWithEthereum(message.getBytes(
        StandardCharsets.UTF_8), userKeys.getPrivate());
    assertFalse(SignatureUtility.verifyPersonalEthereumSignature(message.getBytes(StandardCharsets.UTF_8),
        normalSignature, userKeys.getPublic()));
    assertTrue(SignatureUtility.verifyEthereumSignature(message.getBytes(StandardCharsets.UTF_8),
        normalSignature, userKeys.getPublic()));
  }

  @Test
  public void verifyingChainId() {
    byte[] signature = new byte[65];
    signature[64] = 27;
    assertEquals(SignatureUtility.getChainIdFromSignature(signature), 0);
    signature[64] = 28;
    assertEquals(SignatureUtility.getChainIdFromSignature(signature), 0);
    signature[64] = 37;
    assertEquals(SignatureUtility.getChainIdFromSignature(signature), 1);
    signature[64] = 42;
    assertEquals(SignatureUtility.getChainIdFromSignature(signature), 3);
  }

  @Test
  public void verifyWrongChain() {
    byte[] msgWithoutPrefix = new byte[] {0x42};
    byte[] personalSignature = SignatureUtility.signPersonalMsgWithEthereum(msgWithoutPrefix, 4, userKeys.getPrivate());
    assertTrue(SignatureUtility.verifyPersonalEthereumSignature(msgWithoutPrefix, personalSignature,
        SignatureUtility.addressFromKey(userKeys.getPublic()), 4));
    assertFalse(SignatureUtility.verifyPersonalEthereumSignature(msgWithoutPrefix, personalSignature, userKeys.getPublic()));
    assertFalse(SignatureUtility.verifyPersonalEthereumSignature(msgWithoutPrefix, personalSignature,
        SignatureUtility.addressFromKey(userKeys.getPublic()), 5));
  }

  @Test
  public void nonEip155Sig() {
    byte[] message = new byte[] {0x42};
    byte[] testSignature = SignatureUtility.signWithEthereum(message, userKeys.getPrivate());
    // Change the normal EIP155 signature to one just storing the parity directly
    testSignature[64] = (byte) (1 - (testSignature[64] % 2));
    String address = SignatureUtility.addressFromKey(userKeys.getPublic());
    AsymmetricKeyParameter key = SignatureUtility.recoverEthPublicKeyFromSignature(message, testSignature);
    assertEquals(address, SignatureUtility.addressFromKey(key));
  }

  private static BigInteger[] signDeterministic(byte[] toSign, AsymmetricKeyParameter key) {
    Digest keccak = new KeccakDigest(256);
    keccak.update(toSign, 0, toSign.length);
    HMacDSAKCalculator randomnessProvider = new HMacDSAKCalculator(keccak);
    byte[] digest = new byte[256/8];
    keccak.doFinal(digest, 0);
    ECDSASigner signer = new ECDSASigner(randomnessProvider);
    signer.init(true, key);
    return signer.generateSignature(digest);
  }

  @Test
  public void failureOnInvalidKeys() {
    ECPoint invalidPoint = SECP256K1_DOMAIN.getCurve().createPoint(SECP256K1.getG().getAffineXCoord().toBigInteger(), SECP256K1.getG().getAffineYCoord().toBigInteger().add(BigInteger.ONE));
    // Not on curve
    assertThrows(IllegalArgumentException.class, () -> new ECDomainParameters(SECP256K1.getCurve(), invalidPoint, SECP256K1.getN(), SECP256K1.getH()));
    // Too big
    assertThrows(IllegalArgumentException.class, () -> new ECPrivateKeyParameters(SECP256K1.getN(), SECP256K1_DOMAIN));
  }

  @Test
  public void rZeroValue() {
    byte[] msg = new byte[] {0x42};
    byte[] rZero = new byte[65];
    Exception e = assertThrows( IllegalArgumentException.class, () -> SignatureUtility.recoverEthPublicKeyFromSignature(msg, rZero));
    assertEquals(e.getMessage(), "R value is not in the range [1, n-1]");
  }

  @Test
  public void sZeroValue() {
    byte[] msg = new byte[] {0x42};
    byte[] sZero = new byte[65];
    sZero[0] = 1;
    Exception e = assertThrows( IllegalArgumentException.class, () -> SignatureUtility.recoverEthPublicKeyFromSignature(msg, sZero));
    assertEquals(e.getMessage(), "S value is not in the range [1, n-1]");
  }

  @Test
  public void differentK() {
    byte[] msg1 = new byte[] {0x42};
    byte[] msg2 = new byte[] {0x66};
    byte[] sig1 = SignatureUtility.signPersonalMsgWithEthereum(msg1, userKeys.getPrivate());
    byte[] sig2 = SignatureUtility.signPersonalMsgWithEthereum(msg2, userKeys.getPrivate());
    byte[] r1 = new byte[32];
    byte[] r2 = new byte[32];
    System.arraycopy(sig1, 0, r1, 0, 32);
    System.arraycopy(sig2, 0, r2, 0, 32);
    assertFalse(Arrays.equals(r1, r2));
  }

  class TestECPublicKeyParameters extends ECPublicKeyParameters {
    public ECPoint q;
    public TestECPublicKeyParameters(ECPoint q, ECDomainParameters parameters) {
      super(parameters.getG().multiply(BigInteger.TEN), parameters);
      this.q = q;
    }

    @Override
    public ECPoint getQ() {
      return q;
    }
  }

  @Test
  public void invalidPk1() {
    byte[] msg = new byte[]{0x42};
    byte[] sig = new byte[]{0x42};
    // point not on curve
    ECPoint invalidPoint = SECP256K1_DOMAIN.getCurve().createPoint(BigInteger.valueOf(42), BigInteger.valueOf(43));
    ECPublicKeyParameters pkOPoint = new TestECPublicKeyParameters(invalidPoint, SECP256K1_DOMAIN);
    Exception e = assertThrows(SecurityException.class, () -> SignatureUtility.verifyEthereumSignature(msg, sig, pkOPoint));
    assertEquals("Invalid point coordinates", e.getMessage());
  }

  @Test
  public void invalidPk2() {
    byte[] msg = new byte[] {0x42};
    byte[] sig = new byte[] {0x42};
    // Point contains 0 coordinate
    ECPublicKeyParameters pkOPoint = new TestECPublicKeyParameters(SECP256K1_DOMAIN.getCurve().getInfinity(), SECP256K1_DOMAIN);
    Exception e = assertThrows(SecurityException.class, () -> SignatureUtility.verifyEthereumSignature(msg, sig, pkOPoint));
  }


  @Test
  public void pointOfInf1() {
    ECPoint OPoint = SECP256K1_DOMAIN.getCurve().createPoint(BigInteger.ZERO, BigInteger.ZERO);
    Exception e = assertThrows(IllegalArgumentException.class, () -> new ECPublicKeyParameters(OPoint, SECP256K1_DOMAIN));
    assertEquals("Point not on curve", e.getMessage());
  }

  @Test
  public void pointOfInf2() {
    ECPoint OPoint = SECP256K1_DOMAIN.getCurve().createPoint(BigInteger.ZERO, BigInteger.ONE);
    Exception e = assertThrows(IllegalArgumentException.class, () -> new ECPublicKeyParameters(OPoint, SECP256K1_DOMAIN));
    assertEquals("Point not on curve", e.getMessage());
  }

  @Test
  public void pointOfInf3() {
    ECPoint OPoint = SECP256K1.getCurve().getInfinity();
    Exception e = assertThrows(IllegalArgumentException.class, () -> new ECPublicKeyParameters(OPoint, SECP256K1_DOMAIN));
    assertEquals("Point at infinity", e.getMessage());
  }

  @Test
  public void sunshineStandardEC() {
    byte[] msg = new byte[]{0x01, 0x02};
    byte[] sig = signWithStandardScheme(msg, largeKeys);
    assertTrue(verifyWithStandardScheme(msg, sig, largeKeys.getPublic()));
  }

  @Test
  public void sunshineStandardRSA() {
    RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
    RSAKeyGenerationParameters subjectParam = new RSAKeyGenerationParameters(new BigInteger("65537"), rand, 2048, 80);
    rsaGen.init(subjectParam);
    AsymmetricCipherKeyPair rsa = rsaGen.generateKeyPair();
    byte[] msg = new byte[]{0x01, 0x02};

    byte[] sig = signWithStandardScheme(msg, rsa);
    assertTrue(verifyWithStandardScheme(msg, sig, rsa.getPublic()));
  }

  @Test
  public void badStandardSig() {
    assertThrows(IllegalArgumentException.class, () -> SignatureUtility.verifyWithStandardScheme(new byte[]{0x01}, new byte[65], largeKeys.getPublic()));
  }

  @Test
  public void badStandardSig2() {
    assertFalse(SignatureUtility.verifyWithStandardScheme(new byte[]{0x01}, new byte[65], userKeys.getPublic()));
  }

  @Test
  public void unknownKeyFormat() {
    byte[] msg = new byte[]{0x01, 0x02};
    Ed448KeyPairGenerator gen = new Ed448KeyPairGenerator();
    gen.init(new Ed448KeyGenerationParameters(rand));
    AsymmetricCipherKeyPair keys = gen.generateKeyPair();
    assertThrows(IllegalArgumentException.class, () -> SignatureUtility.signWithStandardScheme(msg, keys));
  }
}
