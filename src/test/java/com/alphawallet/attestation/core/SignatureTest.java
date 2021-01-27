package com.alphawallet.attestation.core;

import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SignatureTest {
  private static final X9ECParameters SECP364R1 = SECNamedCurves.getByName("secp384r1");
  private AsymmetricCipherKeyPair keys;
  private SecureRandom rand;
  private AttestationCrypto crypto;

  @BeforeEach
  public void setupCrypto() throws NoSuchAlgorithmException {
    Security.addProvider(new BouncyCastleProvider());
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    keys = crypto.constructECKeys(SECP364R1);
  }

  @Test
  public void testKeyConversion() throws Exception {
    byte[] message = "test".getBytes(StandardCharsets.UTF_8);
    MessageDigest sha256 = new SHA256.Digest();
    sha256.reset();
    sha256.update(message);
    byte[] digest = sha256.digest();
    byte[] bcSignature = SignatureUtility.signHashedRandomized(digest, keys.getPrivate());

    ECPrivateKey javaPriv = (ECPrivateKey) SignatureUtility.PrivateBCKeyToJavaKey(keys.getPrivate());
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(javaPriv);
    signer.update(message);
    byte[] javaSignature = signer.sign();

    ECPublicKey javaPub = (ECPublicKey) SignatureUtility.PublicBCKeyToJavaKey(keys.getPublic());
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(javaPub);
    verifier.update(message);
    assertTrue(verifier.verify(javaSignature));

    verifier.initVerify(javaPub);
    verifier.update(message);
    assertTrue(verifier.verify(bcSignature));

    assertTrue(SignatureUtility.verifyHashed(digest, javaSignature, keys.getPublic()));
    assertTrue(SignatureUtility.verifyHashed(digest, bcSignature, keys.getPublic()));
  }
}
