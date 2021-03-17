package com.alphawallet.attestation.demo;

import com.alphawallet.attestation.core.AttestationCrypto;
import java.security.SecureRandom;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestDemo {
  private static final String PREFIX = "build/test-results/";
  @BeforeAll
  public static void cleanup() throws Exception {
    SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    // Set the demo to use deterministic randomness
    Demo.crypto = new AttestationCrypto(rand);
    Demo.rand = rand;
  }

  @Test
  public void constructKeys() {
    String[] args;
    // Keys
    args = new String[]{"keys", PREFIX + "sender-pub.pem", PREFIX + "sender-priv.pem"};
    Demo.main(args);
    args = new String[]{"keys", PREFIX + "receiver-pub.pem", PREFIX + "receiver-priv.pem"};
    Demo.main(args);
    args = new String[]{"keys", PREFIX + "attestor-pub.pem", PREFIX + "attestor-priv.pem"};
    Demo.main(args);
  }

  @Test
  public void executeFlow() {
    String[] args;
    // Send
    args = new String[]{"create-cheque", "42", "test@test.ts", "mail", "3600", PREFIX + "sender-priv.pem", PREFIX + "cheque.pem", PREFIX + "cheque-secret.pem"};
    Demo.main(args);
    // Request attestation
    args = new String[]{"request-attest", PREFIX + "receiver-priv.pem", "test@test.ts", "mail", PREFIX + "attestation-request.pem", PREFIX + "attestation-secret.pem"};
    Demo.main(args);
    // Construct attestation
    args = new String[]{"construct-attest", PREFIX + "attestor-priv.pem", "AlphaWallet", "3600", PREFIX + "attestation-request.pem", PREFIX + "attestation.pem"};
    Demo.main(args);
    // Redeem
    args = new String[]{"receive-cheque", PREFIX + "receiver-priv.pem", PREFIX + "cheque-secret.pem", PREFIX + "attestation-secret.pem", PREFIX + "cheque.pem", PREFIX + "attestation.pem", PREFIX + "attestor-pub.pem"};
    Demo.main(args);
  }
}
