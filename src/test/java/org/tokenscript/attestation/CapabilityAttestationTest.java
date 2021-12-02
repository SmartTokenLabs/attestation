package org.tokenscript.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.tokenscript.attestation.CapabilityAttestation.CapabilityType;
import org.tokenscript.attestation.core.SignatureUtility;

public class CapabilityAttestationTest {
  private static final String SOURCE_DOMAIN = "http://www.attesattion.io/";
  private static final String TARGET_DOMAIN = "http://www.hotelbogota.com/";
  private static final BigInteger UNIQUE_ID = new BigInteger("48646584086435845000110053401056");
  private static final Set<CapabilityType> CAPABILITIES = new HashSet<CapabilityType>();
  private static final Instant NOT_BEFORE = Clock.systemUTC().instant();
  private static final Instant NOT_AFTER = NOT_BEFORE.plusSeconds(3600); // One hour

  private static AsymmetricCipherKeyPair issuerKeys;
  private static SecureRandom rand;

  @Mock
  UseAttestation mockedTicket;

  @BeforeEach
  public void init() {
    MockitoAnnotations.initMocks(this);
  }

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());
    issuerKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    CAPABILITIES.add(CapabilityType.READ);
    CAPABILITIES.add(CapabilityType.DELEGATE);
  }

  @Test
  public void sunshine() throws Exception {
    CapabilityAttestation capabilityAttestation = new CapabilityAttestation(UNIQUE_ID, SOURCE_DOMAIN, TARGET_DOMAIN, NOT_BEFORE, NOT_AFTER, CAPABILITIES, issuerKeys);
    assertTrue(capabilityAttestation.checkValidity());
    assertTrue(capabilityAttestation.verify());

    assertEquals(UNIQUE_ID, capabilityAttestation.getUniqueId());
    assertEquals(SOURCE_DOMAIN, capabilityAttestation.getSourceDomain());
    assertEquals(TARGET_DOMAIN, capabilityAttestation.getTargetDomain());
    for (CapabilityType capability : capabilityAttestation.getCapabilities()) {
      assertTrue(CAPABILITIES.contains(capability));
    }
  }

  @Test
  public void consistentEncoding() throws Exception {
    CapabilityAttestation capabilityAttestation = new CapabilityAttestation(UNIQUE_ID, SOURCE_DOMAIN, TARGET_DOMAIN, NOT_BEFORE, NOT_AFTER, CAPABILITIES, issuerKeys);
    CapabilityAttestationDecoder decoder = new CapabilityAttestationDecoder(issuerKeys.getPublic());
    CapabilityAttestation decodedAtt = decoder.decode(capabilityAttestation.getDerEncoding());
    assertArrayEquals(decodedAtt.getDerEncoding(), capabilityAttestation.getDerEncoding());
    assertTrue(decodedAtt.checkValidity());
    assertTrue(decodedAtt.verify());
  }

  @Test
  public void consistentCapabilities() {
    Set<CapabilityType> capabilities = Set.of(CapabilityType.DELEGATE, CapabilityType.WRITE);
    byte[] capabilitiesBytes = CapabilityAttestation.convertToBitString(capabilities);
    Set<CapabilityType> restoredSet = CapabilityAttestationDecoder.convertToSet(capabilitiesBytes);
    assertTrue(restoredSet.contains(CapabilityType.WRITE));
    assertTrue(restoredSet.contains(CapabilityType.DELEGATE));
    assertTrue(restoredSet.size() == 2);
  }

  @Test
  public void mapConsistency() throws Exception {
    assertEquals(CapabilityType.READ, CapabilityType.getType("read"));
    assertEquals(CapabilityType.WRITE, CapabilityType.getType("write"));
    assertEquals(CapabilityType.DELEGATE, CapabilityType.getType("delegate"));
  }

  @Test
  public void multipleKeys() throws Exception {
    String otherDomain = "http://www.not-the-right-source.com";
    AsymmetricCipherKeyPair otherKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    Map<String, AsymmetricKeyParameter> domainKeyMap = Map.of(otherDomain, otherKeys.getPublic(), SOURCE_DOMAIN, issuerKeys.getPublic());
    CapabilityAttestationDecoder decoder = new CapabilityAttestationDecoder(domainKeyMap);
    CapabilityAttestation capabilityAttestation = new CapabilityAttestation(UNIQUE_ID, SOURCE_DOMAIN, TARGET_DOMAIN, NOT_BEFORE, NOT_AFTER, CAPABILITIES, issuerKeys);
    CapabilityAttestation decodedAtt = decoder.decode(capabilityAttestation.getDerEncoding());
    assertTrue(decodedAtt.checkValidity());
    assertTrue(decodedAtt.verify());
  }

  @Test
  public void noValidKey() throws Exception {
    AsymmetricCipherKeyPair otherKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    CapabilityAttestationDecoder decoder = new CapabilityAttestationDecoder(otherKeys.getPublic());
    CapabilityAttestation capabilityAttestation = new CapabilityAttestation(UNIQUE_ID, SOURCE_DOMAIN, TARGET_DOMAIN, NOT_BEFORE, NOT_AFTER, CAPABILITIES, issuerKeys);
    assertThrows(IllegalArgumentException.class, ()-> decoder.decode(capabilityAttestation.getDerEncoding()));
  }

  @Test
  public void invalidTargetDomain() {
    assertThrows(MalformedURLException.class, () -> new CapabilityAttestation(UNIQUE_ID,
        SOURCE_DOMAIN, "not-a-domain.com", NOT_BEFORE, NOT_AFTER, CAPABILITIES, issuerKeys));
  }

  @Test
  public void invalidSourceDomain() {
    assertThrows(MalformedURLException.class, () -> new CapabilityAttestation(UNIQUE_ID,
        "not-a-domain.com", TARGET_DOMAIN, NOT_BEFORE, NOT_AFTER, CAPABILITIES, issuerKeys));
  }

  @Test
  public void wrongVerificationKey() {
    AsymmetricCipherKeyPair otherKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    AsymmetricCipherKeyPair wrongKeyPair = new AsymmetricCipherKeyPair(otherKeys.getPublic(), issuerKeys.getPrivate());
    assertThrows(RuntimeException.class, () -> new CapabilityAttestation(UNIQUE_ID,
        SOURCE_DOMAIN, TARGET_DOMAIN, NOT_BEFORE, NOT_AFTER, CAPABILITIES, wrongKeyPair));
  }

  @Test
  public void notYetValid() throws Exception {
    // Only valid in 24 hours
    CapabilityAttestation capabilityAttestation = new CapabilityAttestation(UNIQUE_ID,
        SOURCE_DOMAIN, TARGET_DOMAIN, Instant.now().plusSeconds(3600*24), NOT_AFTER, CAPABILITIES, issuerKeys);
    assertFalse(capabilityAttestation.checkValidity());
    assertTrue(capabilityAttestation.verify());
  }

  @Test
  public void expired() throws Exception {
    // Only valid in 24 hours
    CapabilityAttestation capabilityAttestation = new CapabilityAttestation(UNIQUE_ID,
        SOURCE_DOMAIN, TARGET_DOMAIN, NOT_BEFORE, NOT_BEFORE.minusSeconds(3600*24), CAPABILITIES, issuerKeys);
    assertFalse(capabilityAttestation.checkValidity());
    assertTrue(capabilityAttestation.verify());
  }
}
