package org.devcon.ticket;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.FullProofOfExponent;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.core.AttestationCrypto;

public class PublicIdentifierProofTest {
  private static final String MAIL = "test@test.ts";
  private static final BigInteger SECRET = new BigInteger("546048445646851568430134455064804806");
  private static final byte[] commitment = AttestationCrypto.makeCommitment(MAIL, AttestationType.EMAIL, SECRET);

  private static SecureRandom rand;
  private static AttestationCrypto crypto;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
  }

  @Test
  public void sunshine() throws Exception {
    PublicIdentifierProof pok = new PublicIdentifierProof(crypto, commitment, MAIL,
        AttestationType.EMAIL, SECRET);
    assertTrue(pok.verify());
  }

  @Test
  public void otherConstructor() {
    PublicIdentifierProof firstConstructor = new PublicIdentifierProof(crypto, commitment, MAIL,
        AttestationType.EMAIL, SECRET);
    PublicIdentifierProof secondConstructor = new PublicIdentifierProof(commitment, MAIL,
        AttestationType.EMAIL, firstConstructor.getInternalPok());
    assertTrue(secondConstructor.verify());
  }

  @Test
  public void randomizedEncoding() {
    PublicIdentifierProof firstConstructor = new PublicIdentifierProof(crypto, commitment, MAIL,
        AttestationType.EMAIL, SECRET);
    PublicIdentifierProof secondConstructor = new PublicIdentifierProof(crypto, commitment, MAIL,
        AttestationType.EMAIL, SECRET);
    assertTrue(!Arrays.equals(firstConstructor.getInternalPok().getDerEncoding(),
        secondConstructor.getInternalPok().getDerEncoding()));
  }

  @Test
  public void wrongEmail() {
    assertThrows(IllegalArgumentException.class, () -> new PublicIdentifierProof(crypto, commitment, "wrong@mail.no",
        AttestationType.EMAIL, SECRET));
  }

  @Test
  public void wrongSecret() {
    byte[] wrongCommitment = AttestationCrypto.makeCommitment(MAIL, AttestationType.EMAIL,
        new BigInteger("123456"));
    assertThrows(IllegalArgumentException.class, () -> new PublicIdentifierProof(crypto, wrongCommitment, MAIL,
        AttestationType.EMAIL, SECRET));
  }

  @Test
  public void wrongInternalPok() {
    PublicIdentifierProof pok = new PublicIdentifierProof(crypto, commitment, MAIL,
        AttestationType.EMAIL, SECRET);
    assertTrue(pok.verify());

    FullProofOfExponent internalPok = pok.getInternalPok();
    FullProofOfExponent newPok = new FullProofOfExponent(internalPok.getRiddle(), internalPok.getPoint(), internalPok.getChallengeResponse().add(BigInteger.ONE));
    assertThrows(IllegalArgumentException.class, () -> new PublicIdentifierProof(commitment, MAIL,
        AttestationType.EMAIL, newPok));
  }
}
