package com.alphawallet.attestation.eip712;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.HelperTest;
import com.alphawallet.attestation.IdentifierAttestation;
import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.SignedIdentityAttestation;
import com.alphawallet.attestation.UseAttestation;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.eip712.Eip712AttestationUsageEncoder.AttestationUsageData;
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
import org.tokenscript.eip712.Eip712Issuer;
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
  private static SignedIdentityAttestation signedAttestation;
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
    attestorKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    AsymmetricCipherKeyPair userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    userSigningKey = userKeys.getPrivate();
    userAddress = SignatureUtility.addressFromKey(userKeys.getPublic());
    nonce = Nonce.makeNonce(userAddress, DOMAIN, new Timestamp());
    pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    IdentifierAttestation att = HelperTest
        .makeUnsignedStandardAtt(userKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    signedAttestation = new SignedIdentityAttestation(att, attestorKeys);
    X9ECParameters SECT283K1 = SECNamedCurves.getByName("sect283k1");
    sessionKey = SignatureUtility.constructECKeys(SECT283K1, rand).getPublic();
  }

  @BeforeEach
  public void init() {
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void referenceJsonFormat() {
    String request = "{\"signatureInHex\":\"0x3ff49ba89f753b52ab8a0b049abbe9652f5eece89a59fa5d78e3b8eb4d2268ca2edf789661058e7733f0b6d1c5b3ac20a56341e546a7a192f59f3dde18ca50421c\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"}]},\\\"primaryType\\\":\\\"AttestationUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIIEkTCCAkAwggHtoAMCARICAQEwCQYHKoZIzj0EAjAOMQwwCgYDVQQDDANBTFgwIhgPMjAyMTA3MDUxNTM0NTBaGA8yMDMxMDcwMzE1MzQ1MFowCzEJMAcGA1UEAwwAMIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA_____________________________________v___C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5hIOtp3JqPEZV2k-_wOEQio_Re0SKaFVBmcR9CP-xDUuAIhAP____________________66rtzmr0igO7_SXozQNkFBAgEBA0IABNNj3-rhhwxBABhmJpTmPZzkcJ6mElV8GFTdL8aGGsseXxiO8jZNWjDMFSqKAPOHT8sVZV66_uNVTxKQgDgZ8_EwBwIBKgICBTmjVzBVMFMGCysGAQQBizpzeQEoAQH_BEEEBf4waGibxLr-xOtIPTqSyPUm7VhND0Wemc6TpRIpCgQVYa-Hh9BK_SkBIguxAbZb1l_SGiHV9mTj-uzDq4UDCTAJBgcqhkjOPQQCA0IAtVTsH1zbPcshTxk65v3JCOxde_XCjoH-lmhvd0vWz3svDzX4_hU9rHX-MkwevIsNhmehVKb06_uiw7YWy-ymtRsCAQEwgfwEQQQetkj_nYGbQHpsWNJ5eHI8TltFCsmJgzzs9v2HwxYM3gmt2VZXjp4go3k37qEfTU2rXXKDOCK7sM0lL_g54kG3BCAIJzMqtsI0IAkmMErEuJDo6P4dJYkQWUH2ExiwMM7t9gRBBAKjw20pLRnqnXDGhXa7hPTienIja7A1OFy7OFMPMnXzHnYNIpLQk6Jaw9fXIYAjeGRG-6XPEqD1b2ynr9XqFUYEUjBYNUY3QkZFNzUyQUMxQTQ1RjY3NDk3RDlEQ0REOUJCREE1MEE4Mzk1NcBxJpS6VWwViG_3TFMX3w_C5Rk1h9lTxNkbTSZP6dyrAAABendOyZAwggFHMIH4BgcqhkjOPQIBMIHsAgEBMCUGByqGSM49AQIwGgICARsGCSqGSM49AQIDAzAJAgEFAgEHAgEMMEwEJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBEkEBQMhP3jKRIg_GjuBYvGI5VPNJl8jwVZ6FodpE7DCrCRYSSg2AczaOA8cnjGNkPldB-VCb-h-RcDoGEaY5FliNk40EWF33SJZAiQB_______________________pri7QdXcmXf9_lEUeBh4WPGECAQQDSgAEBrbPzAjIZQbTVg_wyi-g-i5Y8enp3KEgIAp_3gVQHPFi9F4JBdAYY8OidIjbIitj_UW6hi4fYbTbheWaGoSu3hl2A2BvjwLY\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identity\\\\\\\" is the identity hidden in attestation contained in\\\\\\\"payload\\\\\\\".\\\",\\\"timestamp\\\":\\\"Mon Jul 5 2021 15:34:51 GMT+0000\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Wed Jul 5 10051 14:34:50 GMT+0000\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.hotelbogota.com\\\",\\\"version\\\":\\\"0.1\\\",\\\"chainId\\\":42}}\"}";
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
    Eip712Issuer issuer = new Eip712Issuer<AttestationUsageData>(userSigningKey, encoder);
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
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, -1, CHAIN_ID,
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
    SignedIdentityAttestation otherSingedAttestation = new SignedIdentityAttestation(att, attestorKeys);
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
