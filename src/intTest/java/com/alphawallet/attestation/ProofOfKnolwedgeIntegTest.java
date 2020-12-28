package com.alphawallet.attestation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.demo.SmartContract;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class ProofOfKnolwedgeIntegTest {
    private static AttestationCrypto crypto;
    private static SecureRandom rand;

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG");
        rand.setSeed("seed".getBytes());
        crypto = new AttestationCrypto(rand);
    }

    @Test
    public void TestContract() {
        SmartContract sc = new SmartContract();
        // TODO @James B this is where we need to use verifyEqualityProof and computeEqualityProof
        for (int i = 0; i < 30; i++) {
            byte[] bytes = new byte[32];
            rand.nextBytes(bytes);
            BigInteger rVal = new BigInteger(bytes);
            ProofOfExponent pok = crypto.computeAttestationProof(rVal);
            assertTrue(crypto.verifyAttestationRequestProof(pok));
            assertTrue(sc.testEncoding(pok));
        }

        //now check fail
        for (int i = 0; i < 5; i++) {
            byte[] bytes = new byte[32];
            rand.nextBytes(bytes);
            BigInteger rVal = new BigInteger(bytes);
            ProofOfExponent pok = crypto.computeAttestationProof(rVal);
            assertTrue(crypto.verifyAttestationRequestProof(pok));
            ProofOfExponent newPok = new ProofOfExponent(pok.getBase(), pok.getRiddle(), pok.getPoint(), pok.getChallenge().add(BigInteger.ONE));
            assertFalse(sc.testEncoding(newPok));
        }
    }

}
