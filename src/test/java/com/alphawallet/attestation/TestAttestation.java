package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestAttestation {

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
        Date later = new Date(System.currentTimeMillis()+1000);
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
    public void testMakeUnsignedX509Attestation() throws IOException {
        byte[] res = TestHelper.makeUnsignedx509Att(subjectKeys.getPublic()).getPrehash();
        assertTrue(res != null);
        Path p = Files.createTempFile("unsigned_x509", ".der");
        System.out.println("To check the unsigned X509 attestation, run this:");
        System.out.println("$ openssl asn1parse -inform DER -in " + p.toString());
        Files.write(p, res);
    }

    @Test
    public void testInvalid() {
        Attestation res = TestHelper.makeMinimalAtt();
        res.setDataObject(null);
        assertFalse(res.checkValidity());
    }

    @Test
    public void testInvalidx509() throws IOException {
        Attestation res = TestHelper.makeUnsignedx509Att(subjectKeys.getPublic());
        res.setSmartcontracts(Arrays.asList(13L));
        assertFalse(res.isValidX509());
    }

    @Test
    public void testFullDecoding() throws Exception {
        byte[] encoding = TestHelper.makeMaximalAtt(subjectKeys.getPublic()).getPrehash();
        Attestation newAtt = new Attestation(encoding);
        assertArrayEquals(encoding, newAtt.getPrehash());
    }

    @Test
    public void testMinimalDecoding() throws Exception {
        byte[] encoding = TestHelper.makeMinimalAtt().getPrehash();
        Attestation newAtt = new Attestation(encoding);
        assertArrayEquals(encoding, newAtt.getPrehash());
    }
}

