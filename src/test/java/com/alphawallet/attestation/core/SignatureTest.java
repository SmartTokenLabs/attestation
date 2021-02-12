package com.alphawallet.attestation.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SignatureTest {
  private static final X9ECParameters SECP364R1 = SECNamedCurves.getByName("secp384r1");
  private AsymmetricCipherKeyPair keys;
  private AsymmetricCipherKeyPair userKeys;
  private SecureRandom rand;

  @BeforeEach
  public void setupCrypto() throws NoSuchAlgorithmException {
    Security.addProvider(new BouncyCastleProvider());
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    keys = SignatureUtility.constructECKeys(SECP364R1, rand);
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

  @Test
  public void testKeyConversion() throws Exception {
    byte[] message = "test".getBytes(StandardCharsets.UTF_8);
    MessageDigest sha256 = new SHA256.Digest();
    sha256.reset();
    sha256.update(message);
    byte[] digest = sha256.digest();
    byte[] bcSignature = SignatureUtility.signHashedRandomized(digest, keys.getPrivate());

    ECPrivateKey javaPriv = (ECPrivateKey) SignatureUtility.convertPrivateBouncyCastleKeyToJavaKey(keys.getPrivate());
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(javaPriv);
    signer.update(message);
    byte[] javaSignature = signer.sign();

    ECPublicKey javaPub = (ECPublicKey) SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(keys.getPublic());
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(javaPub);
    verifier.update(message);
    assertTrue(verifier.verify(javaSignature));

    verifier.initVerify(javaPub);
    verifier.update(message);
    assertTrue(verifier.verify(bcSignature));

    assertTrue(SignatureUtility.verifyHashed(digest, javaSignature, keys.getPublic()));
    assertTrue(SignatureUtility.verifyHashed(digest, bcSignature, keys.getPublic()));
    keys = SignatureUtility.constructECKeys(SECP364R1, rand);
    userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

  @Test
  public void testSignDeterministic() {
    byte[] message = new byte[515];
    message[0] = 42;
    message[514] = 13;

    byte[] signature = SignatureUtility.signDeterministic(message, keys.getPrivate());
    assertTrue(SignatureUtility.verify(message, signature, keys.getPublic()));
  }

  @Test
  public void testSignRandomized() {
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
    byte[] signature = SignatureUtility.signWithEthereum(message, userKeys);
    assertTrue(SignatureUtility.verifyEthereumSignature(message, signature, userKeys.getPublic()));
  }

  @Test
  public void testEthereumSigningNewChain() {
    byte[] message = new byte[515];
    message[0] = 41;
    message[514] = 45;
    byte[] signature = SignatureUtility.signWithEthereum(message, 2, userKeys);
    assertTrue(SignatureUtility.verifyEthereumSignature(message, signature, userKeys.getPublic()));
  }

  @Test
  public void testEthereumSigningAgainstReference() {
    for (int i = 0; i < 50; i++) {
      // We make an extra long message and ensure that both the first and last bytes are not 0
      byte[] message = new byte[515];
      message[0] = 0x42;
      message[514] = (byte) i;

      BigInteger[] ourSig = SignatureUtility
          .computeInternalSignature(message, (ECPrivateKeyParameters) userKeys.getPrivate());
      BigInteger[] refSig = signDeterministic(message, userKeys.getPrivate());
      // We need to adjust the s part of the signature if it happens to be
      // less than N/2+1 since these are the only valid Ethereum signatures.
      if (refSig[1].compareTo(SignatureUtility.ECDSAdomain.getN().shiftRight(1)) > 0) {
        refSig[1] = SignatureUtility.ECDSAdomain.getN().subtract(refSig[1]);
      }
      assertEquals(refSig[0], ourSig[0]);
      assertEquals(refSig[1], ourSig[1]);
    }
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
