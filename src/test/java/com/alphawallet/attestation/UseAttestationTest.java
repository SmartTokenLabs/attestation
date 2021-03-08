package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class UseAttestationTest {
  public static final BigInteger SECRET1 = new BigInteger("8646810452103546854685768135857");
  public static final BigInteger SECRET2 = new BigInteger("43854346503445438654346854346854");
  public static final String ID = "test@test.ts";
  public static final byte[] NONCE = new byte[] {0x66};
  private static AsymmetricCipherKeyPair subjectKeys;
  private static AsymmetricCipherKeyPair issuerKeys;

  private static AttestationCrypto crypto;
  private static SecureRandom rand;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    X9ECParameters SECP364R1 = SECNamedCurves.getByName("secp384r1");
    issuerKeys = SignatureUtility.constructECKeys(SECP364R1, rand);
  }

  @Test
  public void sunshine() {
    FullProofOfExponent pok = crypto.computeAttestationProof(SECRET1);
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), SECRET2, ID );
    SignedIdentityAttestation signed = new SignedIdentityAttestation(att, issuerKeys);
    UseAttestation useAttestation = new UseAttestation(signed, pok);
    assertTrue(useAttestation.verify());
    assertTrue(useAttestation.checkValidity());
  }

  @Test
  public void consistentDecoding() {
    FullProofOfExponent pok = crypto.computeAttestationProof(SECRET1, NONCE);
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), SECRET2, ID);
    SignedIdentityAttestation signed = new SignedIdentityAttestation(att, issuerKeys);
    UseAttestation useAttestation = new UseAttestation(signed, pok);
    UseAttestation otherConstructor = new UseAttestation(useAttestation.getDerEncoding(), issuerKeys.getPublic());
    assertTrue(otherConstructor.verify());
    assertTrue(otherConstructor.checkValidity());
    assertArrayEquals(useAttestation.getDerEncoding(), otherConstructor.getDerEncoding());
    // Internal randomness is used in pok construction
    FullProofOfExponent otherPok = crypto.computeAttestationProof(SECRET1, NONCE);
    UseAttestation otherUseAttestation = new UseAttestation(signed, otherPok);
    assertTrue(otherUseAttestation.verify());
    assertTrue(otherUseAttestation.checkValidity());
    assertFalse(Arrays.equals(useAttestation.getDerEncoding(), otherUseAttestation.getDerEncoding()));
  }

  @Test
  public void badPok() {
    FullProofOfExponent pok = crypto.computeAttestationProof(SECRET1, NONCE);
    FullProofOfExponent badPok = new FullProofOfExponent(pok.getRiddle(), pok.getPoint(), pok.getChallenge(), new byte[] {0x01} );
    assertFalse(AttestationCrypto.verifyFullProof(badPok));
    IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), SECRET2, ID);
    SignedIdentityAttestation signed = new SignedIdentityAttestation(att, issuerKeys);
    assertThrows(IllegalArgumentException.class, ()-> new UseAttestation(signed, badPok));
  }

}
