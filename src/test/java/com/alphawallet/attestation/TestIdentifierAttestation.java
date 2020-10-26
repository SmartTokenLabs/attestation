package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.apache.logging.log4j.core.util.Assert;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestIdentifierAttestation {
  private static AsymmetricCipherKeyPair subjectKeys;
  private static SecureRandom rand;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    AttestationCrypto crypto = new AttestationCrypto(rand);
    subjectKeys = crypto.constructECKeys();
  }

  @Test
  public void testFullDecoding() throws Exception {
    IdentifierAttestation initial = TestHelper.makeUnsignedStandardAtt(subjectKeys.getPublic(), BigInteger.ONE);
    byte[] encoding = initial.getDerEncoding();
    Attestation newAtt = new IdentifierAttestation(encoding);
    assertArrayEquals(encoding, newAtt.getPrehash());
  }

  @Test
  public void testNotStandard() throws Exception {
    Attestation initial = TestHelper.makeUnsignedx509Att(subjectKeys.getPublic());
    byte[] encoding = initial.getPrehash();
    try {
      new IdentifierAttestation(encoding);
      fail();
    } catch (IllegalArgumentException e) {
      // Expected
    }
  }

}
