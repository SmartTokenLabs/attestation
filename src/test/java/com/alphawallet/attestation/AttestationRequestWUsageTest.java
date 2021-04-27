package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class AttestationRequestWUsageTest {
  public static final BigInteger SECRET1 = new BigInteger("8646810452103546854685768135857");
  private static final AttestationType TYPE = AttestationType.EMAIL;
  public static final byte[] NONCE = new byte[] {0x66};
  private static AsymmetricKeyParameter sessionKey;

  private static AttestationCrypto crypto;
  private static SecureRandom rand;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    X9ECParameters SECT283K1 = SECNamedCurves.getByName("sect283k1");
    sessionKey = SignatureUtility.constructECKeys(SECT283K1, rand).getPublic();
  }

  @Test
  public void sunshine() {
    FullProofOfExponent pok = crypto.computeAttestationProof(SECRET1, NONCE);
    AttestationRequestWithUsage useAttestation = new AttestationRequestWithUsage(TYPE, pok, sessionKey);
    assertTrue(useAttestation.verify());
  }

  @Test
  public void consistentDecoding() throws Exception {
    FullProofOfExponent pok = crypto.computeAttestationProof(SECRET1, NONCE);
    AttestationRequestWithUsage requestWithUsage = new AttestationRequestWithUsage(TYPE, pok, sessionKey);
    AttestationRequestWithUsage otherConstructor = new AttestationRequestWithUsage(requestWithUsage.getDerEncoding());
    assertTrue(otherConstructor.verify());
    assertEquals(TYPE, otherConstructor.getType());
    assertArrayEquals(pok.getDerEncoding(), otherConstructor.getPok().getDerEncoding());
    assertArrayEquals(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(sessionKey).getEncoded(),
        SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(otherConstructor.getSessionPublicKey()).getEncoded());
    assertArrayEquals(requestWithUsage.getDerEncoding(), otherConstructor.getDerEncoding());
    // Internal randomness is used in pok construction
    FullProofOfExponent otherPok = crypto.computeAttestationProof(SECRET1, NONCE);
    AttestationRequestWithUsage otherRequestWithUsage = new AttestationRequestWithUsage(TYPE, otherPok, sessionKey);
    assertTrue(otherRequestWithUsage.verify());
    assertFalse(Arrays.equals(requestWithUsage.getDerEncoding(), otherRequestWithUsage.getDerEncoding()));
  }

  @Test
  public void badPok() {
    FullProofOfExponent pok = crypto.computeAttestationProof(SECRET1, NONCE);
    FullProofOfExponent badPok = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallenge(), new byte[] {0x01} );
    assertFalse(AttestationCrypto.verifyFullProof(badPok));
    assertThrows(IllegalArgumentException.class, ()-> new AttestationRequestWithUsage(TYPE, badPok, sessionKey));
  }

  @Test
  public void badData() {
    FullProofOfExponent pok = crypto.computeAttestationProof(SECRET1, NONCE);
    AttestationRequestWithUsage requestWithUsage = new AttestationRequestWithUsage(TYPE, pok, sessionKey);
    byte[] encoding = requestWithUsage.getDerEncoding();
    encoding[10] ^= 0x01;
    assertThrows(RuntimeException.class, ()-> new AttestationRequestWithUsage(encoding));
  }

}
