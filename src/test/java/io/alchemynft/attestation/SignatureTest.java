package io.alchemynft.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.core.SignatureUtility;

public class SignatureTest {

  private static AsymmetricCipherKeyPair subjectKeys;
  private static SecureRandom rand;
  private static final byte[] MSG = "some message".getBytes(StandardCharsets.UTF_8);

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());
    subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }

  @Test
  public void personal() {
    AbstractSignature sig = new PersonalSignature(subjectKeys, MSG);
    sunshine(sig);
    ensureProcessing(sig);
    wrongMessage(sig);
    wrongKeys(sig);
  }

  @Test
  public void raw() {
    AbstractSignature sig = new RawSignature(subjectKeys, MSG);
    sunshine(sig);
    wrongMessage(sig);
    wrongKeys(sig);
  }

  @Test
  public void compressed() {
    Signature sig = new CompressedMsgSignature(subjectKeys, MSG);
    sunshine(sig);
    wrongMessage(sig);
    wrongKeys(sig);
  }


  @Test
  public void expectedRaw() {
    AbstractSignature sig = new RawSignature(subjectKeys, MSG);
    assertArrayEquals(sig.getRawSignature(), SignatureUtility.signWithEthereum(MSG, subjectKeys.getPrivate()));
    assertEquals(sig.getTypeOfSignature(), "raw");
    Arrays.equals(sig.processMessage(MSG), MSG);
  }

  @Test
  public void expectedCompressedType() {
    Signature sig = new CompressedMsgSignature(subjectKeys, MSG, "prefix ", " postfix");
    assertEquals(sig.getTypeOfSignature(), "compressed");
  }

  @Test
  public void otherConstructorRaw() {
    Signature sig = new RawSignature(subjectKeys, MSG);
    Signature newSig = new RawSignature(sig.getRawSignature());
    sunshine(newSig);
    assertArrayEquals(sig.getRawSignature(), newSig.getRawSignature());
  }

  @Test
  public void expectedPersonal() {
    Signature sig = new PersonalSignature(subjectKeys, MSG);
    assertArrayEquals(sig.getRawSignature(), SignatureUtility.signPersonalMsgWithEthereum(MSG, subjectKeys.getPrivate()));
    assertEquals(sig.getTypeOfSignature(), "personal");
  }

  @Test
  public void compressedReference() {
    CompressedMsgSignature sig = new CompressedMsgSignature(subjectKeys, MSG, "prefix ", " postfix");
    assertArrayEquals(sig.processMessage(MSG), "prefix 0x9DF8DBA3720D00BD48AD744722021EF91B035E273BCCFB78660CA8DF9574B086 postfix".getBytes(
        StandardCharsets.UTF_8));
  }

  @Test
  public void otherConstructorPersonal() {
    Signature sig = new PersonalSignature(subjectKeys, MSG);
    Signature newSig = new PersonalSignature(sig.getRawSignature());
    sunshine(newSig);
    assertArrayEquals(sig.getRawSignature(), newSig.getRawSignature());
  }

  @Test
  public void otherConstructorCompressed() {
    Signature sig = new CompressedMsgSignature(subjectKeys, MSG);
    Signature newSig = new CompressedMsgSignature(sig.getRawSignature());
    sunshine(newSig);
    assertArrayEquals(sig.getRawSignature(), newSig.getRawSignature());
  }

  public void sunshine(Signature sig) {
    assertNotNull(sig.getRawSignature());
    assertTrue(sig.getRawSignature().length > 5);
    assertTrue(sig.verify(MSG, subjectKeys.getPublic()));
  }

  public void ensureProcessing(AbstractSignature sig) {
    assertFalse(Arrays.equals(sig.processMessage(MSG), MSG));
  }

  public void wrongMessage(Signature sig) {
    assertFalse(sig.verify("some other message".getBytes(StandardCharsets.UTF_8), subjectKeys.getPublic()));
  }

  public void wrongKeys(Signature sig) {
    assertFalse(sig.verify(MSG, SignatureUtility.constructECKeysWithSmallestY(rand).getPublic()));
  }
}
