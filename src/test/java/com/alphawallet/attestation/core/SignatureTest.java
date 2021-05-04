package com.alphawallet.attestation.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SignatureTest {
  private static final X9ECParameters SECP364R1 = SECNamedCurves.getByName("secp384r1");
  private AsymmetricCipherKeyPair largeKeys;
  private AsymmetricCipherKeyPair userKeys;
  private SecureRandom rand;

  @BeforeEach
  public void setupCrypto() throws NoSuchAlgorithmException {
    Security.addProvider(new BouncyCastleProvider());
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    largeKeys = SignatureUtility.constructECKeys(SECP364R1, rand);
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

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
  public void testSignDeterministic() {
    byte[] message = new byte[515];
    message[0] = 42;
    message[514] = 13;

    byte[] signature = SignatureUtility.signDeterministicSHA256(message, largeKeys.getPrivate());
    assertTrue(SignatureUtility.verifySHA256(message, signature, largeKeys.getPublic()));
  }

  @Test
  public void testSignRandomized() {
    for (int i = 0; i < 50; i++) {
      byte[] message = new byte[256];
      message[0] = 0x42;
      message[255] = (byte) i;

      byte[] signature = SignatureUtility.signHashedRandomized(message, largeKeys.getPrivate());
      assertTrue(SignatureUtility.verifyHashed(message, signature, largeKeys.getPublic()));
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
      if (refSig[1].compareTo(SignatureUtility.ECDSA_DOMAIN.getN().shiftRight(1)) > 0) {
        refSig[1] = SignatureUtility.ECDSA_DOMAIN.getN().subtract(refSig[1]);
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
}
