package com.alphawallet.attestation.core;


import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/*
 * One of the Ethereum design is, instead of verifying a message
 * against a known public key, a v value is included in the signature,
 * allowing an Ethereum address to be recovered from a message. The
 * advantage of this design is that message doesn't have to carry the
 * sender's Etheruem address, yet allowing a smart contract to check
 * the message against a dictionary of possible senders.

 * For example, Alice sends a cheque for Bob to redeem an ERC20
 * token. She doesn't need to include her Ethereum address as it can
 * be determined from the signature; the smart contract, instead of
 * verifying it against a large array of known users, can use the
 * recovered Ethereum address to look up the remaining balance.

 * This design is great however it breaks X9.62 key format:
 * ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }

 * In the scenario where the public key is known, a smart contract can
 * simply store the v value together with the public key; however, in
 * other situations, to avoid attempting v value 2 times, we can
 * selectively only use keys which result in a fixed v value. This
 * class replaced the constructECKeys() method just to do that.
 */

public class AttestationCryptoWithEthereumCharacteristics extends AttestationCrypto {
    public AttestationCryptoWithEthereumCharacteristics(SecureRandom rand) {
        super(rand);
    }

    public AsymmetricCipherKeyPair constructECKeys() {
        AsymmetricCipherKeyPair keys;
        BigInteger yCoord;
        BigInteger fieldModulo = ECDSAdomain.getCurve().getField().getCharacteristic();
        // If the y coordinate is in the upper half of the field, then sample again until it to the lower half
        do {
            keys = super.constructECKeys();
            ECPublicKeyParameters pk = (ECPublicKeyParameters) keys.getPublic();
            yCoord = pk.getQ().getYCoord().toBigInteger();
        } while (yCoord.compareTo(fieldModulo.shiftRight(1)) > 0);
        return keys;
    }

}
