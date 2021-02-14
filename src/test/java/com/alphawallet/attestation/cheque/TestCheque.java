package com.alphawallet.attestation.cheque;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import java.io.IOException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestCheque {
  private static AsymmetricCipherKeyPair senderKeys;
  private static SecureRandom rand;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    senderKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
  }


  @Test
  public void testChequeURLSunshine() throws IOException {
    BigInteger senderSecret = new BigInteger("112");
    Cheque cheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, senderSecret);

    byte[] senderPublicKey = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(senderKeys.getPublic()).getPublicKeyData().getEncoded();
    String url = URLUtility.encodeList(Arrays.asList(cheque.getDerEncoding(), senderPublicKey));

    List<byte[]> decoded = URLUtility.decodeList(url);
    Cheque newCheque = (new ChequeDecoder()).decode(decoded.get(0));
    assertTrue(newCheque.verify());
    assertTrue(newCheque.checkValidity());
    assertArrayEquals(cheque.getDerEncoding(), newCheque.getDerEncoding());

    AsymmetricKeyParameter newIssuerPublicKey = SignatureUtility.restoreDefaultKey(decoded.get(1));
    Cheque otherConstructorCheque = new Cheque(newCheque.getCommitment(), newCheque.getAmount(),
        newCheque.getNotValidBefore(), newCheque.getNotValidAfter(), newCheque.getSignature(), newIssuerPublicKey);
    assertArrayEquals(cheque.getDerEncoding(), otherConstructorCheque.getDerEncoding());
  }

  @Test
  public void testChequeURLConsistentEncoding() throws IOException {
    BigInteger senderSecret = new BigInteger("112");
    Cheque cheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, senderSecret);
    String url = URLUtility.encodeData(cheque.getDerEncoding());
    Cheque newCheque =  (new ChequeDecoder()).decode(URLUtility.decodeData(url));
    String newUrl = URLUtility.encodeData(newCheque.getDerEncoding());
    assertEquals(url, newUrl);
  }

  @Test
  public void testFullDecoding() throws Exception {
    Cheque cheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, BigInteger.TEN);
    byte[] encoded = cheque.getDerEncoding();
    Cheque newCheque = (new ChequeDecoder()).decode(encoded);
    assertTrue(cheque.verify());
    assertTrue(cheque.checkValidity());
    assertArrayEquals(encoded, newCheque.getDerEncoding());

    Cheque otherConstructor = new Cheque(newCheque.getCommitment(), newCheque.getAmount(),
        newCheque.getNotValidBefore(), newCheque.getNotValidAfter(), newCheque.getSignature(),
        newCheque.getPublicKey());
    assertEquals(cheque.getAmount(), otherConstructor.getAmount());
    assertEquals(cheque.getNotValidBefore(), otherConstructor.getNotValidBefore());
    assertEquals(cheque.getNotValidAfter(), otherConstructor.getNotValidAfter());
    assertArrayEquals(cheque.getCommitment(), otherConstructor.getCommitment());
    assertArrayEquals(cheque.getSignature(), otherConstructor.getSignature());
    SubjectPublicKeyInfo chequeSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(cheque.getPublicKey());
    SubjectPublicKeyInfo otherSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(otherConstructor.getPublicKey());
    assertArrayEquals(chequeSpki.getEncoded(), otherSpki.getEncoded());

    assertArrayEquals(encoded, otherConstructor.getDerEncoding());
  }

  @Test
  public void testIllegalKeys() throws Exception {
    Cheque cheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, 3600000, senderKeys, BigInteger.TEN);
    Field field = cheque.getClass().getDeclaredField("signature");
    field.setAccessible(true);
    // Change a bit in the signature
    ((byte[]) field.get(cheque))[20] ^= 1;
    assertFalse(cheque.verify());
  }

  @Test
  public void testInvalid() {
    Cheque cheque = new Cheque("test@test.ts", AttestationType.EMAIL, 1000, -1000, senderKeys, BigInteger.TEN);
    assertFalse(cheque.checkValidity());
  }

}
