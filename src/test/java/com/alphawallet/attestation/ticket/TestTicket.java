package com.alphawallet.attestation.ticket;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.cheque.Cheque;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.ticket.Ticket.TicketClass;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class TestTicket {
  private static AsymmetricCipherKeyPair senderKeys;
  private static SecureRandom rand;

  @BeforeAll
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    AttestationCrypto crypto = new AttestationCrypto(rand);
    senderKeys = crypto.constructECKeys();
  }

  @Test
  public void testFullDecoding() throws Exception {
    AlgorithmIdentifier identifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(AttestationCrypto.OID_SIGNATURE_ALG));
    Ticket ticket = new Ticket(new BigInteger("58954"), TicketClass.SPEAKER, 6, new byte[1], identifier, new byte[1]);
//    byte[] encoded = cheque.getDerEncoding();
//    Cheque newCheque = new Cheque(encoded);
//    assertTrue(cheque.verify());
//    assertTrue(cheque.checkValidity());
//    assertArrayEquals(encoded, newCheque.getDerEncoding());
//
//    Cheque otherConstructor = new Cheque(newCheque.getRiddle(), newCheque.getAmount(),
//        newCheque.getNotValidBefore(), newCheque.getNotValidAfter(), newCheque.getSignature(),
//        newCheque.getPublicKey());
//    assertEquals(cheque.getAmount(), otherConstructor.getAmount());
//    assertEquals(cheque.getNotValidBefore(), otherConstructor.getNotValidBefore());
//    assertEquals(cheque.getNotValidAfter(), otherConstructor.getNotValidAfter());
//    assertArrayEquals(cheque.getRiddle(), otherConstructor.getRiddle());
//    assertArrayEquals(cheque.getSignature(), otherConstructor.getSignature());
//    // Note that apparently a proper equality has not been implemented for AsymmetricKeyParameter
////    Assert.assertEquals(cheque.getPublicKey(), otherConstructor.getPublicKey());
//    assertArrayEquals(encoded, otherConstructor.getDerEncoding());
  }
}
