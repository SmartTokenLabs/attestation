package org.devcon.ticket;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import java.math.BigInteger;
import java.net.URL;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class CapabilityTest {
  private static final X9ECParameters SECP384R1 = SECNamedCurves.getByName("secp384r1");
  private static final String receiverDomain = "http://www.hotelbogota.com";
  private static final String verifierDomain = "http://www.ticket.devcon.org";

  private static AsymmetricCipherKeyPair ticketKeys;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;
  private static CapabilityIssuer issuer;
  private static CapabilityValidator validator;
  private static Set<String> tasks;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    ticketKeys = SignatureUtility.constructECKeys(SECP384R1, rand);
    issuer = new CapabilityIssuer(ticketKeys, verifierDomain);
    validator = new CapabilityValidator(ticketKeys.getPublic(), verifierDomain);
    tasks = new HashSet<>();
    tasks.add("discount");
    tasks.add("ICO");
    tasks.add("IPO");
    tasks.add("mail");
  }

  @Test
  public void legalRequest() throws Exception {
    String token = issuer.makeToken(receiverDomain, tasks, 31);
    assertTrue(validator.validateRequest(token, receiverDomain, tasks));
  }

  @Test
  public void rsaKeys() throws Exception {
    AsymmetricCipherKeyPair rsaKeys = getRsaKeys();
    CapabilityIssuer rsaIssuer = new CapabilityIssuer(rsaKeys, verifierDomain);
    CapabilityValidator rsaValidator = new CapabilityValidator(rsaKeys.getPublic(), verifierDomain);
    String token = rsaIssuer.makeToken(receiverDomain, tasks, 31);
    assertTrue(rsaValidator.validateRequest(token, receiverDomain, tasks));
  }

  private AsymmetricCipherKeyPair getRsaKeys() {
    RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
    generator.init(
        new RSAKeyGenerationParameters(
            new BigInteger("65537"), rand, 2048, 0));
    return generator.generateKeyPair();
  }

  @Test
  public void legalSetOfSubtasks() throws Exception {
    String token = issuer.makeToken(receiverDomain, tasks, 31);
    Set<String> neededTasks = new HashSet<>();
    neededTasks.add("iPo");
    neededTasks.add(" ico ");
    assertTrue(validator.validateRequest(token, receiverDomain, neededTasks));
  }

  @Test
  public void missingTask() throws Exception {
    Set<String> tasks = new HashSet<>();
    tasks.add("discount");
    String token = issuer.makeToken(receiverDomain, tasks, 31);
    Set<String> neededTasks = new HashSet<>();
    neededTasks.add("ico");
    assertFalse(validator.validateRequest(token, receiverDomain, neededTasks));
  }

  @Test
  public void wrongReceiver() throws Exception {
    String token = issuer.makeToken(receiverDomain, tasks, 31);
    // .org instead of .com
    assertFalse(validator.validateRequest(token, "http://www.hotelbogota.org", tasks));
  }

  @Test
  public void wrongAudience() throws Exception {
    CapabilityValidator newValidator = new CapabilityValidator(ticketKeys.getPublic(), "http://www.evil.org");
    String token = issuer.makeToken(receiverDomain, tasks, 31);
    // .org instead of .com
    assertFalse(newValidator.validateRequest(token, receiverDomain, tasks));
  }

  @Test
  public void wrongIssuer() throws Exception {
    CapabilityIssuer newIssuer = new CapabilityIssuer(ticketKeys, "http://www.evil.org");
    String token = newIssuer.makeToken(receiverDomain, tasks, 31);
    // .org instead of .com
    assertFalse(validator.validateRequest(token, receiverDomain, tasks));
  }

  @Test
  public void invalidTask() {
    Set<String> tasks = new HashSet<>();
    tasks.add("discount");
    tasks.add("IC,O");
    assertThrows(IllegalArgumentException.class, () -> issuer.makeToken(receiverDomain, tasks, 31));
  }

  @Test
  public void notValidAnymore() throws Exception {
    String token = issuer.makeToken(receiverDomain, tasks, 0);
    // At least a second must pass since the underlying granularity is to the second
    Thread.sleep(1001);
    // .org instead of .com
    assertFalse(validator.validateRequest(token, receiverDomain, tasks));
  }

  @Test
  public void notYetValid() throws Exception {
    long current = System.currentTimeMillis();
    String flattenedTasks = issuer.flattenSet(tasks);
    String token = issuer.buildSignedToken(new URL(receiverDomain), flattenedTasks,
        current + 10000, current + 5000);
    assertFalse(validator.validateRequest(token, receiverDomain, tasks));
  }

  @Test
  public void emptySetIssued() {
    Set<String> tasks = new HashSet<>();
    assertThrows(IllegalArgumentException.class, () -> issuer.makeToken(receiverDomain, tasks, 31));
  }

  @Test
  public void emptySetValidated() throws Exception {
    String token = issuer.makeToken(receiverDomain, tasks, 31);
    assertFalse(validator.validateRequest(token, receiverDomain, new HashSet<>()));
  }

  @Test
  public void unitFlattenedList() {
    assertEquals("ico,mail,discount,ipo", issuer.flattenSet(tasks));
  }

}
