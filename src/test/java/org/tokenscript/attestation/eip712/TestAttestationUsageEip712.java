package org.tokenscript.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.tokenscript.attestation.FullProofOfExponent;
import org.tokenscript.attestation.HelperTest;
import org.tokenscript.attestation.IdentifierAttestation;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.SignedIdentifierAttestation;
import org.tokenscript.attestation.Timestamp;
import org.tokenscript.attestation.UseAttestation;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.URLUtility;
import org.tokenscript.attestation.eip712.Eip712AttestationUsageEncoder.AttestationUsageData;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.tokenscript.eip712.Eip712Signer;
import org.tokenscript.eip712.Eip712Test;

public class TestAttestationUsageEip712 {
  private static final String DOMAIN = "https://www.hotelbogota.com";
  private static final String MAIL = "email@test.com";
  private static final AttestationType TYPE = AttestationType.EMAIL;
  private static final BigInteger ATTESTATION_SECRET = new BigInteger("15816808484023");
  private static final long CHAIN_ID = 1;
  private static final Eip712AttestationUsageEncoder encoder = new Eip712AttestationUsageEncoder(CHAIN_ID);

  private static byte[] nonce;
  private static FullProofOfExponent pok;
  private static SignedIdentifierAttestation signedAttestation;
  private static AsymmetricCipherKeyPair attestorKeys;
  private static AsymmetricKeyParameter userSigningKey;
  private static AsymmetricKeyParameter sessionKey;
  private static String userAddress;
  private static SecureRandom rand;
  private static AttestationCrypto crypto;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    // added sender keys to align keys with DEMO. keys order changed.
    AsymmetricCipherKeyPair senderKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    AsymmetricCipherKeyPair userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    attestorKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    userSigningKey = userKeys.getPrivate();
    userAddress = SignatureUtility.addressFromKey(userKeys.getPublic());
    nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    IdentifierAttestation att = HelperTest
        .makeUnsignedStandardAtt(userKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    signedAttestation = new SignedIdentifierAttestation(att, attestorKeys);
    X9ECParameters SECT283K1 = SECNamedCurves.getByName("sect283k1");
    sessionKey = SignatureUtility.constructECKeys(SECT283K1, rand).getPublic();
  }

  @BeforeEach
  public void init() {
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void referenceJsonFormat() {
     String request = "{\"signatureInHex\":\"0x5aee5630bdd0e16c4d89a30181e94b8fc09b793581c60364e08cb052ae2cc742437e7a64865ed7667d32370d4c22d594dc47034e6d943811f8af0ed74704bd511b\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"}]},\\\"primaryType\\\":\\\"AttestationUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIIEoTCCAlAwggH9oAMCARICAQEwCQYHKoZIzj0EAjAOMQwwCgYDVQQDDANBTFgwMhgPMjAyMTExMjgxNzEyMDNaAgYBfWeIQrgYDzIwMzExMTI2MTcxMjAzWgIGAcbUc_q4MAsxCTAHBgNVBAMMADCCATMwgewGByqGSM49AgEwgeACAQEwLAYHKoZIzj0BAQIhAP____________________________________7___wvMEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1LgCIQD____________________-uq7c5q9IoDu_0l6M0DZBQQIBAQNCAATTY9_q4YcMQQAYZiaU5j2c5HCephJVfBhU3S_GhhrLHl8YjvI2TVowzBUqigDzh0_LFWVeuv7jVU8SkIA4GfPxMAcCASoCAgU5o1cwVTBTBgsrBgEEAYs6c3kBKAEB_wRBBAX-MGhom8S6_sTrSD06ksj1Ju1YTQ9FnpnOk6USKQoEFWGvh4fQSv0pASILsQG2W9Zf0hoh1fZk4_rsw6uFAwkwCQYHKoZIzj0EAgNCANjXvx7Yn8Z1QuSvzDRZWNRnRhLG6bJvVxu2KtTKLstkHJNoWdTDxKRyJDQSwmiusfUAgHa_Y4C8Sce117svXucbAgEBMIH8BEEEHrZI_52Bm0B6bFjSeXhyPE5bRQrJiYM87Pb9h8MWDN4JrdlWV46eIKN5N-6hH01Nq11ygzgiu7DNJS_4OeJBtwQgBasR9EVj7LpiU_psPAVGQczjXzjbFfi2PGQIMx5dZl4EQQQLrsh8ULAyPnxsgA84CHjT-4K_bgwaRQhLFFpEVQP5ZCtUE-UdmQO_CpxVcA1k0y9g0xeAa-Pecw2vaZKZ0vcFBFIwWDVGN0JGRTc1MkFDMUE0NUY2NzQ5N0Q5RENERDlCQkRBNTBBODM5NTXAcSaUulVsFYhv90xTF98PwuUZNYfZU8TZG00mT-ncqwAAAX1niEK4MIIBRzCB-AYHKoZIzj0CATCB7AIBATAlBgcqhkjOPQECMBoCAgEbBgkqhkjOPQECAwMwCQIBBQIBBwIBDDBMBCQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQRJBAUDIT94ykSIPxo7gWLxiOVTzSZfI8FWehaHaROwwqwkWEkoNgHM2jgPHJ4xjZD5XQflQm_ofkXA6BhGmORZYjZONBFhd90iWQIkAf______________________6a4u0HV3Jl3_f5RFHgYeFjxhAgEEA0oABASxov7mwoFuyCbYay1wqodZQMRjSyxQH8nltWpppSFHqUcWLQeuYBHZuBToGb7Uk2A6s5uGu3miBVZ9w0556mcgv746eK-7BQ==\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identifier\\\\\\\" is the identifier hidden in attestation contained in\\\\\\\"payload\\\\\\\".\\\",\\\"timestamp\\\":\\\"Sun Nov 28 2021 17:12:07 GMT+0000\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Tue Nov 28 10051 16:12:06 GMT+0000\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.hotelbogota.com\\\",\\\"version\\\":\\\"0.1\\\",\\\"chainId\\\":42}}\"}";
    Eip712AttestationUsage eiprequest = new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(),
        Timestamp.UNLIMITED, 42, request);
    assertTrue(eiprequest.verify());
    assertTrue(eiprequest.checkTokenValidity());
  }

  @Test
  public void testSunshine() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    assertTrue(usage.verify());
    assertTrue(usage.checkValidity());
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  public void otherTimeLimit() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    assertTrue(usage.verify());
    assertTrue(usage.checkValidity());
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN,  Timestamp.UNLIMITED, 42, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  public void testDecoding() throws Exception {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    Eip712AttestationUsage newRequest = new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), request.getJsonEncoding());
    assertTrue(newRequest.verify());
    assertTrue(newRequest.checkTokenValidity());

    assertEquals(request.getIdentifier(), newRequest.getIdentifier());
    assertTrue(AttestationCrypto.verifyFullProof(newRequest.getPok()));
    assertArrayEquals(request.getPok().getDerEncoding(), newRequest.getPok().getDerEncoding());
    assertTrue(newRequest.getAttestation().verify());
    assertTrue(newRequest.getAttestation().checkValidity());
    assertArrayEquals(request.getAttestation().getDerEncoding(), newRequest.getAttestation().getDerEncoding());
    assertEquals(request.getJsonEncoding(), newRequest.getJsonEncoding());
    assertEquals(request.getType(), newRequest.getType());
    assertArrayEquals(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(sessionKey).getEncoded(),
        SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(newRequest.getSessionPublicKey()).getEncoded());
    assertEquals( ((ECKeyParameters) request.getUserPublicKey()).getParameters(),
        ((ECKeyParameters) newRequest.getUserPublicKey()).getParameters());
  }

  @Test
  public void eipEncoding() throws Exception {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    Eip712Test.validateEncoding(encoder, request.getJsonEncoding());
  }

  @Test
  public void eipSignableEncoding() throws Exception {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Timestamp now = new Timestamp();
    Timestamp expirationTime = new Timestamp(now.getTime() + 1000);
    AttestationUsageData data = new AttestationUsageData(
        encoder.getUsageValue(),
        MAIL, URLUtility.encodeData(usage.getDerEncoding()), now, expirationTime);
    Eip712Signer issuer = new Eip712Signer<AttestationUsageData>(userSigningKey, encoder);
    String json = issuer.buildSignedTokenFromJsonObject(data.getSignableVersion(), DOMAIN);
    Eip712Test.validateEncoding(encoder, json);
  }

  @Test
  public void badAttesattion() {
    Mockito.when(mockedUseAttestation.getDerEncoding()).thenReturn(new byte[0]);
    Mockito.when(mockedUseAttestation.verify()).thenReturn(false);
    Exception e = assertThrows(IllegalArgumentException.class, () -> new Eip712AttestationUsage(DOMAIN, MAIL, mockedUseAttestation, userSigningKey));
    assertEquals("Could not verify object", e.getMessage());
  }

  @Test
  public void expiredToken() throws Exception {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, -Timestamp.ALLOWED_ROUNDING*2, CHAIN_ID,
        MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  public void invalidNonceDomain() {
    byte[] wrongNonce = Nonce.makeNonce(userAddress, "http://www.notTheRightHotel.com", new Timestamp());
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, wrongPok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  public void invalidNonceAddress() {
    byte[] wrongNonce = new byte[] {0x01, 0x02, 0x03};
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, wrongPok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  public void invalidNonceBadIdentifier() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, "notTheRight@email.com", usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Mock
  UseAttestation mockedUseAttestation;
  @Test
  public void invalidUseAttestation() {
    Mockito.when(mockedUseAttestation.verify()).thenReturn(true);
    Mockito.when(mockedUseAttestation.getDerEncoding()).thenReturn(new byte[] {0x00});
    Mockito.when(mockedUseAttestation.getAttestation()).thenReturn(signedAttestation);
    Mockito.when(mockedUseAttestation.getPok()).thenReturn(pok);
    Mockito.when(mockedUseAttestation.getType()).thenReturn(TYPE);
    Mockito.when(mockedUseAttestation.checkValidity()).thenReturn(false);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, mockedUseAttestation, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  public void nonverifiableUseAttesation() {
    // First verification is done in the constructor of Eip712AttestationUsage
    Mockito.when(mockedUseAttestation.verify()).thenReturn(true).thenReturn(false);
    Mockito.when(mockedUseAttestation.getDerEncoding()).thenReturn(new byte[] {0x00});
    Mockito.when(mockedUseAttestation.getAttestation()).thenReturn(signedAttestation);
    Mockito.when(mockedUseAttestation.getPok()).thenReturn(pok);
    Mockito.when(mockedUseAttestation.getType()).thenReturn(TYPE);
    Mockito.when(mockedUseAttestation.checkValidity()).thenReturn(true);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, mockedUseAttestation, userSigningKey);
    assertFalse(request.verify());
    assertTrue(request.checkTokenValidity());
  }

  @Test
  public void invalidProofLinking() {
    // Wrong type
    UseAttestation usage = new UseAttestation(signedAttestation, AttestationType.PHONE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkTokenValidity());
  }

  @Test
  public void badAddressInNonce() {
    AsymmetricCipherKeyPair otherUserKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    IdentifierAttestation att = HelperTest
        .makeUnsignedStandardAtt(otherUserKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedIdentifierAttestation otherSingedAttestation = new SignedIdentifierAttestation(att, attestorKeys);
    UseAttestation usage = new UseAttestation(otherSingedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertFalse(request.checkTokenValidity());
  }

  @Test
  public void invalidConstructor() {
    Mockito.when(mockedUseAttestation.verify()).thenReturn(true);
    Mockito.when(mockedUseAttestation.getDerEncoding()).thenReturn(null);
    // Wrong signing keys
    Exception e = assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationUsage(DOMAIN, MAIL, mockedUseAttestation,
        userSigningKey));
    assertEquals("Could not encode asn1", e.getMessage());
  }

  @Test
  public void invalidOtherConstructor() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    String json = request.getJsonEncoding();
    String wrongJson = json.replace(',', '.');
    Exception e = assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), wrongJson));
    assertEquals("Could not decode asn1", e.getMessage());
  }

}
