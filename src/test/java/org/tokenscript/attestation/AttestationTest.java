package org.tokenscript.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.core.SignatureUtility;

public class AttestationTest {

    private static AsymmetricCipherKeyPair subjectKeys;
    private static SecureRandom rand;

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rand.setSeed("seed".getBytes());
        subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
    }

    @Test
    public void testGetterSetter() throws Exception {
        Attestation att = new Attestation();
        att.setVersion(19);
        assertEquals(att.getVersion(), 19);
        att.setSerialNumber(42);
        assertEquals(att.getSerialNumber(), 42);
        att.setIssuer("CN=ALX");
        assertEquals(att.getIssuer(), "CN=ALX");
        Date now = new Date();
        att.setNotValidBefore(now);
        assertEquals(att.getNotValidBefore().toString(), now.toString());
        Date later = new Date(Clock.systemUTC().millis()+1000);
        att.setNotValidAfter(later);
        assertEquals(att.getNotValidAfter().toString(), later.toString());
        att.setSubject("CN=me");
        assertEquals(att.getSubject(), "CN=me");
        SubjectPublicKeyInfo newSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(subjectKeys.getPublic());
        att.setSubjectPublicKeyInfo(newSpki);
        assertEquals(att.getSubjectPublicKeyInfo(), newSpki);
        att.setSmartcontracts(Arrays.asList(42L, 13L));
        assertEquals(att.getSmartcontracts(), Arrays.asList(42L, 13L));
        att.setExtensions(new DERSequence());
        assertEquals(att.getExtensions(), new DERSequence());

        Attestation att2 = new Attestation();
        att2.setDataObject(new DERSequence());
        assertEquals(att2.getDataObject(), new DERSequence());
    }

    @Test
    public void blockchainFriendlyVersion() throws Exception {
        Attestation att = new Attestation();
        att.setVersion(19);
        att.setSerialNumber(42);
        att.setIssuer("CN=ALX");
        Date now = new Date();
        att.setNotValidBefore(now);
        Date later = new Date(Clock.systemUTC().millis()+1000);
        att.setNotValidAfter(later);
        att.setSubject("CN=me");
        SubjectPublicKeyInfo newSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(subjectKeys.getPublic());
        att.setSubjectPublicKeyInfo(newSpki);
        att.setSmartcontracts(Arrays.asList(42L, 13L));
        att.setExtensions(new DERSequence());
        att.setSigningAlgorithm(SignedIdentifierAttestation.ECDSA_WITH_SHA256);
        assertTrue(att.checkValidity());
        //  The blockchain friendly encoding contains more info
        assertFalse(Arrays.equals(att.getPrehash(true), att.getPrehash(false)));
        // Blockchain version still valid
        Attestation newAtt = new Attestation(att.getPrehash(false));
        assertTrue(newAtt.checkValidity());
        assertTrue(newAtt.getPrehash(true).length >att.getPrehash(false).length);
    }

    @Test
    public void testMakeUnsignedX509Attestation() throws IOException {
        byte[] res = HelperTest.makeUnsignedx509Att(subjectKeys.getPublic()).getPrehash();
        assertTrue(res != null);
        Path p = Files.createTempFile("unsigned_x509", ".der");
        System.out.println("To check the unsigned X509 attestation, run this:");
        System.out.println("$ openssl asn1parse -inform DER -in " + p.toString());
        Files.write(p, res);
    }

    @Test
    public void testInvalid() throws Exception {
        Attestation res = HelperTest.makeMinimalAtt();
        ASN1EncodableVector extensions = new ASN1EncodableVector();
        extensions.add(Attestation.OID_OCTETSTRING);
        extensions.add(ASN1Boolean.TRUE);
        extensions.add(new DEROctetString(new byte[] {0x42}));
        Field extensionsField = Attestation.class.getDeclaredField("extensions");
        extensionsField.setAccessible(true);
        extensionsField.set(res, new DERSequence(new DERSequence(extensions)));
        // Both dataObject and extensions have been set, which is not allowed
        assertFalse(res.checkValidity());
    }

    @Test
    public void testInvalidx509() throws IOException {
        Attestation res = HelperTest.makeUnsignedx509Att(subjectKeys.getPublic());
        res.setSmartcontracts(Arrays.asList(13L));
        assertFalse(res.isValidX509());
    }

    @Test
    public void testExpired() throws Exception {
        Attestation res = HelperTest.makeUnsignedx509Att(subjectKeys.getPublic());
        assertTrue(res.checkValidity());
        assertTrue(res.isValidX509());
        Date almostNow = new Date(Clock.systemUTC().millis() - Timestamp.ALLOWED_ROUNDING - 2000);
        res.setNotValidAfter(almostNow);
        assertFalse(res.checkValidity());
    }

    @Test
    public void testNotYetValid() throws Exception {
        Attestation res = HelperTest.makeUnsignedx509Att(subjectKeys.getPublic());
        assertTrue(res.checkValidity());
        assertTrue(res.isValidX509());
        // We are still within the allowed rounding
        res.setNotValidBefore(new Date(Clock.systemUTC().millis() + Timestamp.ALLOWED_ROUNDING-2000));
        assertTrue(res.checkValidity());
        // We just passed allowed rounding
        res.setNotValidBefore(new Date(Clock.systemUTC().millis() + Timestamp.ALLOWED_ROUNDING+2000));
        assertFalse(res.checkValidity());
    }

    @Test
    public void testFullDecoding() throws Exception {
        byte[] encoding = HelperTest.makeMaximalAtt(subjectKeys.getPublic()).getPrehash();
        Attestation newAtt = new Attestation(encoding);
        assertArrayEquals(encoding, newAtt.getPrehash());
    }

    @Test
    public void testMinimalDecoding() throws Exception {
        byte[] encoding = HelperTest.makeMinimalAtt().getPrehash();
        Attestation newAtt = new Attestation(encoding);
        assertArrayEquals(encoding, newAtt.getPrehash());
    }

    @Test
    public void inconsistentNotBefore() {
        String attString = "MIIBp6ADAgETAgEqMAoGCCqGSM49BAMCMA4xDDAKBgNVBAMMA0FMWDAvGA8yMDIyMDMyNDEyMzExM1oCBGI8ZJIYDzk5OTkxMjMxMjI1OTU5WgIFOv/0M28wDTELMAkGA1UEAwwCbWUwggEzMIHsBgcqhkjOPQIBMIHgAgEBMCwGByqGSM49AQECIQD////////////////////////////////////+///8LzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcEQQR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEg62ncmo8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA/////////////////////rqu3OavSKA7v9JejNA2QUECAQEDQgAElQx8C+0jw8rFzDG7uarZu1UyOHiCZwrCsc3weZqw68dkwmf3BOj92geWq4OXpNIQECTSTE7/9pWzpBfy7Q5IzTAGAgEqAgENowIwAA==";
        Exception exception = assertThrows(IllegalArgumentException.class, ()-> new Attestation(Base64.decode(attString)));
        assertEquals(exception.getMessage(),"NotValidBefore integer encoding is inconsistent with the GeneralizedTime encoding");
    }

    @Test
    public void inconsistentNotAfter() {
        String attString = "MIIBp6ADAgETAgEqMAoGCCqGSM49BAMCMA4xDDAKBgNVBAMMA0FMWDAvGA8yMDIyMDMyNDEyMzQyNVoCBGI8ZVEYDzk5OTkxMjMxMjI1OTU5WgIFOv/0M3AwDTELMAkGA1UEAwwCbWUwggEzMIHsBgcqhkjOPQIBMIHgAgEBMCwGByqGSM49AQECIQD////////////////////////////////////+///8LzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcEQQR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEg62ncmo8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA/////////////////////rqu3OavSKA7v9JejNA2QUECAQEDQgAElQx8C+0jw8rFzDG7uarZu1UyOHiCZwrCsc3weZqw68dkwmf3BOj92geWq4OXpNIQECTSTE7/9pWzpBfy7Q5IzTAGAgEqAgENowIwAA==";
        Exception exception = assertThrows(IllegalArgumentException.class, ()->  new Attestation(Base64.decode(attString)));
        assertEquals(exception.getMessage(),"NotValidAfter integer encoding is inconsistent with the GeneralizedTime encoding");
    }
}

