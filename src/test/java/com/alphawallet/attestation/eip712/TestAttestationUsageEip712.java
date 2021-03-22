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
import java.nio.charset.StandardCharsets;
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
    nonce = Nonce.makeNonce(MAIL, userAddress, DOMAIN, Clock.systemUTC().millis());
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
    String request = "{\"signatureInHex\":\"0x1ad02d3f6289b78f6732a3ec2bc6c7fed5fcd2e22d803bd3cfd4f033dfe738443c3f3f3532e4bf455433bfe2cfa5b01f5933b0938df2e9bca37399986e1a6e5d1c\",\"jsonSigned\":\"{\\\"types\\\":{\\\"AttestationUsage\\\":[{\\\"name\\\":\\\"payload\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"description\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"timestamp\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"identifier\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"expirationTime\\\",\\\"type\\\":\\\"string\\\"}],\\\"EIP712Domain\\\":[{\\\"name\\\":\\\"name\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"version\\\",\\\"type\\\":\\\"string\\\"},{\\\"name\\\":\\\"chainId\\\",\\\"type\\\":\\\"uint256\\\"}]},\\\"primaryType\\\":\\\"AttestationUsage\\\",\\\"message\\\":{\\\"payload\\\":\\\"MIIFDTCCApEwggIYoAMCARICAQEwCgYIKoZIzj0EAwIwDjEMMAoGA1UEAwwDQUxYMCIYDzIwMjEwMzIyMTYxMjA2WhgPMjAyMTAzMjIxNzEyMDZaMDUxMzAxBgNVBAMMKjB4NUFFRTJCOUE4NjU2NDk2MDMyQTY0N0UxMzY2RTFBQTY3NUZGQ0I3NzCCATMwgewGByqGSM49AgEwgeACAQEwLAYHKoZIzj0BAQIhAP____________________________________7___wvMEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1LgCIQD____________________-uq7c5q9IoDu_0l6M0DZBQQIBAQNCAATpSkUyWoWaOvDxhNbg1x06S1fw_Xac_1bJzUuxqP0kynF3_OZ_SKTBz-mvunuyqG5aVYoGBh1jv0O3f-erPm7jMAcCASoCAgU5o1cwVTBTBgsrBgEEAYs6c3kBKAEB_wRBBAX-MGhom8S6_sTrSD06ksj1Ju1YTQ9FnpnOk6USKQoEFWGvh4fQSv0pASILsQG2W9Zf0hoh1fZk4_rsw6uFAwkwCgYIKoZIzj0EAwIDZwAwZAIwYvTZZ3aL-5_g7dDt41qupJ266fWIx9Y-vD3SK30PWuz-Gk-8oWApN0hYQ6MQHGljAjBvBDV_vJ_ySqL4S1M_7-812_XaCdU9kMc69PilyPIOLH6A9mxipP4Vllwrr1Pe4nYCAQEwggEmBEEEHrZI_52Bm0B6bFjSeXhyPE5bRQrJiYM87Pb9h8MWDN4JrdlWV46eIKN5N-6hH01Nq11ygzgiu7DNJS_4OeJBtwQgA4TcJ2ZaJE0qATF91FAGTuAlA70kA_pFHFMBQQJhQrIEQQQX4Z1T_ffcZPouAoZw7qc_L6dptIdcijVo3hR_l1-EMyCZncll2mkcpUahvF_Y1VvHZuwvR7TpLmk5DTaqg42tBHwAAAF4WrUsX75fBHxNKfUzo3WVOF5FzoG62wQCYndzY0zWAqc7WT-fWu4rmoZWSWAypkfhNm4apnX_y3fAcSaUulVsFYhv90xTF98PwuUZNYfZU8TZG00mT-ncq8XSRgGG9yM8kn59stzHA8DlALZTyoInO3v62ARdhaRwMIIBRzCB-AYHKoZIzj0CATCB7AIBATAlBgcqhkjOPQECMBoCAgEbBgkqhkjOPQECAwMwCQIBBQIBBwIBDDBMBCQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQRJBAUDIT94ykSIPxo7gWLxiOVTzSZfI8FWehaHaROwwqwkWEkoNgHM2jgPHJ4xjZD5XQflQm_ofkXA6BhGmORZYjZONBFhd90iWQIkAf______________________6a4u0HV3Jl3_f5RFHgYeFjxhAgEEA0oABAG5IWXCs0dd0mgXFWbn4ptLS585WSIzGnuQjtGmbKwDhZJaygZYM36AXoJA1cJI0YBXM8-f2207T0YKcNmZMI2dW4nH1nGm8w==\\\",\\\"description\\\":\\\"Prove that the \\\\\\\"identity\\\\\\\" is the identity hidden in attestation contained in\\\\\\\"payload\\\\\\\".\\\",\\\"timestamp\\\":\\\"Mon Mar 22 2021 17:12:06 GMT+0100\\\",\\\"identifier\\\":\\\"email@test.com\\\",\\\"expirationTime\\\":\\\"Mon Mar 22 2021 17:42:06 GMT+0100\\\"},\\\"domain\\\":{\\\"name\\\":\\\"https://www.hotelbogota.com\\\",\\\"version\\\":\\\"0.1\\\",\\\"chainId\\\":0}}\"}";
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
    Eip712Test.validateEncoding(new Eip712AttestationUsageEncoder(CHAIN_ID), request.getJsonEncoding());
  }

  @Test
  public void eipSignableEncoding() throws Exception {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    long now = Clock.systemUTC().millis();
    long expirationTime = now + 1000;
    AttestationUsageData data = new AttestationUsageData(
        Eip712AttestationUsageEncoder.USAGE_VALUE,
        MAIL, URLUtility.encodeData(usage.getDerEncoding()), now, expirationTime);
    Eip712Issuer issuer = new Eip712Issuer<AttestationUsageData>(userSigningKey, new Eip712AttestationUsageEncoder(CHAIN_ID));
    String json = issuer.buildSignedTokenFromJsonObject(data.getSignableVersion(), DOMAIN);
    Eip712Test.validateEncoding(new Eip712AttestationUsageEncoder(CHAIN_ID), json);
  }

  @Test
  public void badSignature() {
      UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
      Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    byte[] encoding = request.getJsonEncoding().getBytes(StandardCharsets.UTF_8);
    // Flip a bit in the signature part of the encoding
    encoding[40] ^= 0x01;
    assertThrows(IllegalArgumentException.class,
        () -> new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), new String(encoding)));
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
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, -100, Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT, CHAIN_ID ,
        MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }

  @Test
  public void timestampInFuture() {
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsageEncoder encoder = new Eip712AttestationUsageEncoder(CHAIN_ID);
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
    Eip712AttestationUsageEncoder encoder = new Eip712AttestationUsageEncoder(CHAIN_ID);
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
    Eip712AttestationUsageEncoder encoder = new Eip712AttestationUsageEncoder(CHAIN_ID);
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
    Eip712AttestationUsageEncoder encoder = new Eip712AttestationUsageEncoder(CHAIN_ID);
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
    Eip712AttestationUsageEncoder encoder = new Eip712AttestationUsageEncoder(CHAIN_ID);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    long timestamp = Clock.systemUTC().millis();
    long expirationTime = timestamp + Eip712AttestationUsage.DEFAULT_TOKEN_TIME_LIMIT;
    String timestampString = encoder.TIMESTAMP_FORMAT.format(new Date(timestamp));
    SimpleDateFormat otherFormat = new SimpleDateFormat("EEE MMM d yyyy HH:mm:ss", Locale.US);
    String expirationTimeString = otherFormat.format(new Date(expirationTime));
    assertFalse(request.validateTime(timestampString, expirationTimeString));
  }

  @Test
  public void invalidNonceDomain() {
    byte[] wrongNonce = Nonce.makeNonce(MAIL, userAddress, "http://www.notTheRightHotel.com",
        Clock.systemUTC().millis());
    FullProofOfExponent wrongPok = crypto.computeAttestationProof(ATTESTATION_SECRET, wrongNonce);
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, wrongPok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    assertTrue(request.verify());
    assertFalse(request.checkValidity());
  }

  @Test
  public void invalidNonceAddress() {
    byte[] wrongNonce = Nonce.makeNonce(MAIL, "0x01234567890123456789", DOMAIN, Clock.systemUTC().millis());
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
  public void badAddressForSignatureVerification() {
    AsymmetricCipherKeyPair otherUserKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    IdentifierAttestation att = HelperTest
        .makeUnsignedStandardAtt(otherUserKeys.getPublic(), attestorKeys.getPublic(), ATTESTATION_SECRET, MAIL);
    SignedIdentityAttestation otherSingedAttestation = new SignedIdentityAttestation(att, attestorKeys);
    UseAttestation usage = new UseAttestation(otherSingedAttestation, TYPE, pok, sessionKey);
    assertThrows(IllegalArgumentException.class, () -> new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey));
  }

  @Test
  public void invalidConstructor() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    // Wrong signing keys
    Exception e = assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationUsage(DOMAIN, MAIL, usage,
        attestorKeys.getPrivate()));
    assertEquals(e.getMessage(), "Could not encode object");
  }

  @Test
  public void invalidOtherConstructor() {
    FullProofOfExponent pok = crypto.computeAttestationProof(ATTESTATION_SECRET);
    UseAttestation usage = new UseAttestation(signedAttestation, TYPE, pok, sessionKey);
    Eip712AttestationUsage request = new Eip712AttestationUsage(DOMAIN, MAIL, usage, userSigningKey);
    String json = request.getJsonEncoding();
    String wrongJson = json.replace(',', '.');
    Exception e = assertThrows( IllegalArgumentException.class, () ->  new Eip712AttestationUsage(DOMAIN, attestorKeys.getPublic(), wrongJson));
    assertEquals(e.getMessage(), "Could not decode object");
  }

}
