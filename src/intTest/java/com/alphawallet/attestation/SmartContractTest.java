package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.demo.SmartContract;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import com.alphawallet.token.tools.Numeric;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class SmartContractTest {
    private static AttestationCrypto crypto;
    private static SecureRandom rand;

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG");
        rand.setSeed("seed".getBytes());
        crypto = new AttestationCrypto(rand);
    }

    private final static Random gen = new Random();

    //Generates a fairly random email address
    private String generateID() {
        return names[gen.nextInt(names.length)].toLowerCase() + "@" +
                names[gen.nextInt(names.length)].toLowerCase() +
                suffixes[gen.nextInt(suffixes.length)];
    }

    static final String[] names = {"Violet",
            "Marcelline",
            "Darlleen",
            "Adelle",
            "Di",
            "Merrie",
            "Asia",
            "Lesly",
            "Fredericka",
            "Anestassia",
            "Brana",
            "Cathie",
            "Joelly",
            "Christian",
            "Elvira",
            "Joelly",
            "Lita",
            "Mahalia",
            "Judy",
            "Marcelline",
            "Belva",
            "Dione",
            "Max",
            "Justin",
            "Roxanne",
            "Tom",
            "Dick",
            "Harry"};

    static final String[] suffixes = {".com",
            ".co.uk",
            ".org",
            ".io",
            ".com.au",
            ".edu",
            ".co",
            ".cn",
            ".jp",
            ".xyz",
            ".eth"};

    @Test
    public void TestContract() throws Exception {
        gen.setSeed(12345678L); //fixed for testing purposes
        SmartContract sc = new SmartContract();

        BigInteger localSecret1 = new BigInteger("5848910840846872525745834000448648789786746461");
        BigInteger localSecret2 = new BigInteger("640848948534656666878789789789484891065000");

        // Equality proof soak test
        for (int i = 0; i < 1000; i++) {
            String id = generateID();
            localSecret1 = localSecret1.add(BigInteger.ONE);
            localSecret2 = localSecret2.add(BigInteger.ONE);
            byte[] com1 = crypto.makeCommitment(id, AttestationType.EMAIL, localSecret1);
            byte[] com2 = crypto.makeCommitment(id, AttestationType.EMAIL, localSecret2);
            ProofOfExponent pok = crypto.computeEqualityProof(com1, com2, localSecret1, localSecret2);
            System.out.println("com1: " + Numeric.toHexString(com1));
            System.out.println("com2: " + Numeric.toHexString(com2));
            System.out.println(Numeric.toHexString(pok.getDerEncoding()));
            assertTrue(crypto.verifyEqualityProof(com1, com2, pok));
            assertTrue(sc.verifyEqualityProof(com1, com2, pok));
        }

        // Negative tests
        for (int i = 0; i < 100; i++) {
            String id = generateID();
            localSecret1 = localSecret1.add(BigInteger.ONE);
            localSecret2 = localSecret2.add(BigInteger.ONE);
            byte[] com1 = crypto.makeCommitment(id, AttestationType.EMAIL, localSecret1);
            byte[] com2 = crypto.makeCommitment(id, AttestationType.EMAIL, localSecret2);
            ProofOfExponent pok = crypto.computeEqualityProof(com1, com2, localSecret1, localSecret2);
            UsageProofOfExponent newPok = new UsageProofOfExponent(pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
            boolean negativeCheck = sc.verifyEqualityProof(com1, com2, newPok);
            System.out.println("-> " + (negativeCheck ? "Contract call should fail! Check Failed" : "Negative check Passed"));
            assertFalse(negativeCheck);
        }

        // ProofOfExponent request proof
        for (int i = 0; i < 10; i++) {
            byte[] com1 = crypto.makeCommitment(generateID(), AttestationType.EMAIL, BigInteger.valueOf(500+i));
            byte[] com2 = crypto.makeCommitment(generateID(), AttestationType.EMAIL, BigInteger.valueOf(1000*i));
            UsageProofOfExponent pok = crypto.computeEqualityProof(com1, com2, BigInteger.valueOf(500+i), BigInteger.valueOf(1000*i));
            assertTrue(crypto.verifyEqualityProof(com1, com2, pok));
            assertTrue(sc.verifyEqualityProof(com1, com2, pok));
        }

        // ProofOfExponent negative test
        for (int i = 0; i < 5; i++) {
            byte[] com1 = crypto.makeCommitment(generateID(), AttestationType.EMAIL, BigInteger.valueOf(500+i));
            byte[] com2 = crypto.makeCommitment(generateID(), AttestationType.EMAIL, BigInteger.valueOf(1000*i));
            UsageProofOfExponent pok = crypto.computeEqualityProof(com1, com2, BigInteger.valueOf(500+i), BigInteger.valueOf(1000*i));
            assertTrue(crypto.verifyEqualityProof(com1, com2, pok));
            UsageProofOfExponent newPok = new UsageProofOfExponent(pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
            boolean negativeCheck = sc.verifyEqualityProof(com1, com2, newPok);
            System.out.println("-> " + (negativeCheck ? "Contract call should fail! Check Failed" : "Negative check Passed"));
            assertFalse(negativeCheck);
        }
    }
}
