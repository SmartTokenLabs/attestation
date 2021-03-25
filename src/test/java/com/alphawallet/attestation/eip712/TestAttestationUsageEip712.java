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
import com.alphawallet.attestation.core.Nonce;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.URLUtility;
import com.alphawallet.attestation.eip712.Eip712AttestationUsageEncoder.AttestationUsageData;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.time.Clock;
import java.util.Date;
import java.util.Locale;
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
import org.tokenscript.eip712.Eip712Validator;

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
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    crypto = new AttestationCrypto(rand);
    attestorKeys = SignatureUtility.constructECKeys(SECNamedCurves.getByName("secp384r1"), rand);
    AsymmetricCipherKeyPair userKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    userSigningKey = userKeys.getPrivate();
    userAddress = SignatureUtility.addressFromKey(userKeys.getPublic());
    nonce = Nonce.makeNonce(userAddress, DOMAIN, Clock.systemUTC().millis());
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
    String request = "{\"signatureInHex\":\"0x7c2a10b60d9295fe0ee2b820c38489b3fbb46a7cc74ed96bbfbaa1bbb7aae28c26b6c7e2814153751b70a041c0081a0a3dae71c6dd2d9a7108c6ce39035521711b\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"}]},\\\"primaryType\\\":\\\"AttestationUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIIE4zCCApIwggIYoAMCARICAQEwCgYIKoZIzj0EAwIwDjEMMAoGA1UEAwwDQUxYMCIYDzIwMjEwMzI1MTUxNjU4WhgPMjAyMTAzMjUxNjE2NThaMDUxMzAxBgNVBAMMKjB4NUFFRTJCOUE4NjU2NDk2MDMyQTY0N0UxMzY2RTFBQTY3NUZGQ0I3NzCCATMwgewGByqGSM49AgEwgeACAQEwLAYHKoZIzj0BAQIhAP____________________________________7___wvMEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1LgCIQD____________________-uq7c5q9IoDu_0l6M0DZBQQIBAQNCAATpSkUyWoWaOvDxhNbg1x06S1fw_Xac_1bJzUuxqP0kynF3_OZ_SKTBz-mvunuyqG5aVYoGBh1jv0O3f-erPm7jMAcCASoCAgU5o1cwVTBTBgsrBgEEAYs6c3kBKAEB_wRBBAX-MGhom8S6_sTrSD06ksj1Ju1YTQ9FnpnOk6USKQoEFWGvh4fQSv0pASILsQG2W9Zf0hoh1fZk4_rsw6uFAwkwCgYIKoZIzj0EAwIDaAAwZQIxAPLl32cW4MFIK9doWjEiUMlcns49BJ5bRJPWf0sBc2_Sm_kginyEYnwrw0x3l3vrawIwTLDPNP8yfQw_4h2VqB5zMeDyerWDKlumH78UNwFCLL095qwpjzM3NMnXZe9bpqm1AgEBMIH8BEEEHrZI_52Bm0B6bFjSeXhyPE5bRQrJiYM87Pb9h8MWDN4JrdlWV46eIKN5N-6hH01Nq11ygzgiu7DNJS_4OeJBtwQgB0h3fPqk3NFFbCKL9P5j7-VBh1-_geF9p1852ollgjAEQQQNx8gr1TUaqdeIUkr5TOdqBntV9Aw7vu1A81xDWK0CHwnlxWI1wiPlE5ht4oo-Gu0xfW-q07psaUywzHoYbYEvBFIweDVBRUUyQjlBODY1NjQ5NjAzMkE2NDdFMTM2NkUxQUE2NzVGRkNCNzfAcSaUulVsFYhv90xTF98PwuUZNYfZU8TZG00mT-ncqwAAAXhp9cbBMIIBRzCB-AYHKoZIzj0CATCB7AIBATAlBgcqhkjOPQECMBoCAgEbBgkqhkjOPQECAwMwCQIBBQIBBwIBDDBMBCQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQRJBAUDIT94ykSIPxo7gWLxiOVTzSZfI8FWehaHaROwwqwkWEkoNgHM2jgPHJ4xjZD5XQflQm_ofkXA6BhGmORZYjZONBFhd90iWQIkAf______________________6a4u0HV3Jl3_f5RFHgYeFjxhAgEEA0oABAaKAQV4lid9odpUKH2KardHB0qcxk3gFSFREF-NkUOiPmnTdgXW7EzLFIKWRHiMQlvTsZmTC5UsoaA96mYFXktwQUgqF1IsxA==\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identity\\\\\\\" is the identity hidden in attestation contained in\\\\\\\"payload\\\\\\\".\\\",\\\"timestamp\\\":\\\"Thu Mar 25 2021 16:16:58 GMT+0100\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Thu Apr 1 2021 17:16:58 GMT+0200\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.hotelbogota.com\\\",\\\"version\\\":\\\"0.1\\\",\\\"chainId\\\":0}}\"}";
    Eip712AttestationUsage eiprequest = new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), 1000*60*60*24*365*10, 1000*60*60*24*365*10, Eip712AttestationUsage.PLACEHOLDER_CHAIN_ID, request);
    assertTrue(eiprequest.verify());
    assertTrue(eiprequest.checkValidity());
  }

  @Test
  public void testSunshine() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    assertTrue(usage.verify());
    assertTrue(usage.checkValidity());
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertTrue(request.checkValidity());
  }

  @Test
  public void testDecoding() throws Exception {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    Eip712AttestationUsage newRequest = new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), request.getJsonEncoding());
    assertTrue(newRequest.verify());
    assertTrue(newRequest.checkValidity());

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
    long now = Clock.systemUTC().millis();
    long expirationTime = now + 1000;
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
    assertEquals("Could not verify Eip712 use attestation", e.getMessage());
  }

  @Test
  public void expiredToken() throws Exception {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, Eip712AttestationUsage.DEFAULT_TIME_LIMIT_MS, -1, CHAIN_ID,
        MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }

  @Test
  public void invalidTimestamp() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, -1001, Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT, CHAIN_ID ,
        MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }

  @Test
  public void timestampInFuture() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    long futureTime = Clock.systemUTC().millis() + Eip712Validator.DEFAULT_TIME_LIMIT_MS + 1000;
    long expirationTime = futureTime + Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT;
    String futureTimeString = encoder.TIMESTAMP_FORMAT.format(new Date(futureTime));
    String expirationTimeString = encoder.TIMESTAMP_FORMAT.format(new Date(expirationTime));
    assertFalse(request.validateTime(futureTimeString, expirationTimeString));
  }

  @Test
  public void timestampExpired() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    long timestamp = Clock.systemUTC().millis() - Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT - Eip712Validator.DEFAULT_TIME_LIMIT_MS - 1000;
    long expirationTime = timestamp + Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT;
    String timestampString = encoder.TIMESTAMP_FORMAT.format(new Date(timestamp));
    String expirationTimeString = encoder.TIMESTAMP_FORMAT.format(new Date(expirationTime));
    assertFalse(request.validateTime(timestampString, expirationTimeString));
  }

  @Test
  public void timestampFromPastOk() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    long timestamp = Clock.systemUTC().millis() - Eip712Validator.DEFAULT_TIME_LIMIT_MS - 1000;
    long expirationTime = timestamp + Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT;
    String timestampString = encoder.TIMESTAMP_FORMAT.format(new Date(timestamp));
    String expirationTimeString = encoder.TIMESTAMP_FORMAT.format(new Date(expirationTime));
    assertTrue(request.validateTime(timestampString, expirationTimeString));
  }

  @Test
  public void validForTooLong() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    long timestamp = Clock.systemUTC().millis();
    long expirationTime = timestamp + Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT + Eip712Validator.DEFAULT_TIME_LIMIT_MS + 1;
    String timestampString = encoder.TIMESTAMP_FORMAT.format(new Date(timestamp));
    String expirationTimeString = encoder.TIMESTAMP_FORMAT.format(new Date(expirationTime));
    assertFalse(request.validateTime(timestampString, expirationTimeString));
  }

  @Test
  public void invalidTimeFormat() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    long timestamp = Clock.systemUTC().millis();
    long expirationTime = timestamp + Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT;
    String timestampString = encoder.TIMESTAMP_FORMAT.format(new Date(timestamp));
    SimpleDateFormat otherFormat = new SimpleDateFormat("EEE MMM d yyyy HH:mm:ss", Locale.US);
    String expirationTimeString = otherFormat.format(new Date(expirationTime));
    assertThrows(RuntimeException.class, ()-> request.validateTime(timestampString, expirationTimeString));
  }

  @Test
  public void invalidNonceDomain() {
    byte[] wrongNonce = Nonce.makeNonce(userAddress, "http://www.notTheRightHotel.com", Clock.systemUTC().millis());
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, wrongPok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }

  @Test
  public void invalidNonceAddress() {
    byte[] wrongNonce = new byte[] {0x01, 0x02, 0x03};
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, wrongPok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }

  @Test
  public void invalidNonceBadIdentifier() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, "notTheRight@email.com", usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
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
    assertFalse(request.checkValidity());
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
    assertTrue(request.checkValidity());
  }

  @Test
  public void invalidProofLinking() {
    // Wrong type
    UseAttestation usage = new UseAttestation(signedAttestation, AttestationType.PHONE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }

  @Test
  public void badAddressInNonce() {
    AsymmetricCipherKeyPair otherUserKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    IdentifierAttestation att = HelperTest
        .makeUnsignedStandardAtt(otherUserKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedIdentityAttestation otherSingedAttestation = new SignedIdentityAttestation(att, attestorKeys);
    UseAttestation usage = new UseAttestation(otherSingedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertFalse(request.checkValidity());
  }

  @Test
  public void invalidConstructor() {
    Mockito.when(mockedUseAttestation.verify()).thenReturn(true);
    Mockito.when(mockedUseAttestation.getDerEncoding()).thenReturn(null);
    // Wrong signing keys
    Exception e = assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationUsage(DOMAIN, MAIL, mockedUseAttestation,
        userSigningKey));
    assertEquals("Could not encode object", e.getMessage());
  }

  @Test
  public void invalidOtherConstructor() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET, nonce);
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    String json = request.getJsonEncoding();
    String wrongJson = json.replace(',', '.');
    Exception e = assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), wrongJson));
    assertEquals("Could not decode object", e.getMessage());
  }

}
