package org.tokenscript.attestation.demo;


import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.token.tools.Numeric;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.tokenscript.attestation.HelperTest;
import org.tokenscript.attestation.IdentifierAttestation;
import org.tokenscript.attestation.SignedIdentifierAttestation;
import org.tokenscript.attestation.core.SignatureUtility;
import org.web3j.abi.datatypes.Address;

public class TestAttestationUse {
    private static final String MAIL = "test@test.ts";
    private static final BigInteger ATTESTATION_SECRET = new BigInteger("8408464");

    private static AsymmetricCipherKeyPair subjectKeys;
    private static AsymmetricCipherKeyPair attestorKeys;
    private static SecureRandom rand;
    private SignedIdentifierAttestation attestation;
    private final SmartContract contract = new SmartContract();

    @BeforeAll
    public static void setupKeys() throws Exception {
        rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rand.setSeed("seed".getBytes());

        subjectKeys = SignatureUtility.constructECKeysWithSmallestY(rand);
        attestorKeys = SignatureUtility.constructECKeys(rand);

        System.out.println("Issuer Key Address: " +  SignatureUtility.addressFromKey(attestorKeys.getPublic()));
        System.out.println("Subject Key Address: " +  SignatureUtility.addressFromKey(subjectKeys.getPublic()));
    }

    @BeforeEach
    public void makeAttestedCheque()
    {
        IdentifierAttestation att = HelperTest.makeUnsignedStandardAtt(subjectKeys.getPublic(), ATTESTATION_SECRET, MAIL);
        attestation = new SignedIdentifierAttestation(att, attestorKeys);
    }

    // TODO disabled due to obsolescence of test chain, should be enabled as part of https://github.com/TokenScript/attestation/pull/302
    @Disabled
    @Test
    public void testSendAttestation() {
        // *** PRINT DER ENCODING OF OBJECTS ***
        try {
            byte[] attestationData = attestation.getDerEncoding();

            String subjectAddress = SignatureUtility.addressFromKey(subjectKeys.getPublic());
            String attestorAddress = SignatureUtility.addressFromKey(attestorKeys.getPublic());

            System.out.println("Attestation: " + Numeric.toHexString(attestationData));
            System.out.println("PreHash: " + Numeric.toHexString(attestation.getUnsignedAttestation().getDerEncoding()));

            //Test smart contract decodes the attestation and verifies the content correctly
            //call smart contract to recover subject and attestor key ethereum addresses.
            List<Address> contractAddresses = contract.getAttestationAddresses(attestation);

            assertTrue(contractAddresses.size() == 2);

            System.out.println("Subject address from contract: " + contractAddresses.get(0));
            System.out.println("Attestor address from contract: " + contractAddresses.get(1));

            assertTrue(contractAddresses.get(0).toString().equalsIgnoreCase(subjectAddress));
            assertTrue(contractAddresses.get(1).toString().equalsIgnoreCase(attestorAddress));

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
