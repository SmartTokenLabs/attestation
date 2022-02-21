package org.devcon.ticket;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Proof of concept Ticket system for Liscon.
 * It is significantly less secure than the regular Ticket format and should only be used in legacy settings!
 */
@Deprecated
public class LisconTicket extends Ticket {
  public LisconTicket(String mail, String devconId, BigInteger ticketId, int ticketClass,
      AsymmetricCipherKeyPair keys, BigInteger secret) {
    super(mail, devconId, ticketId, ticketClass, keys, secret);
  }

  public LisconTicket(String devconId, BigInteger ticketId, int ticketClass, byte[] commitment,
      byte[] signature, AsymmetricKeyParameter publicKey) {
    super(devconId, ticketId, ticketClass, commitment, signature, publicKey);
  }

  @Override
  ASN1Sequence makeTicket() {
    ASN1EncodableVector ticket = new ASN1EncodableVector();
    ticket.add(new DERUTF8String(getDevconId()));
    ticket.add(new ASN1Integer(getTicketId()));
    ticket.add(new ASN1Integer(getTicketClass()));
    return new DERSequence(ticket);
  }

  @Override
  byte[] encodeSignedTicket(ASN1Sequence ticket) throws IOException {
    ASN1EncodableVector signedTicket = new ASN1EncodableVector();
    signedTicket.add(ticket);
    signedTicket.add(new DEROctetString(getCommitment()));
    signedTicket.add(new DERBitString(getSignature()));
    return new DERSequence(signedTicket).getEncoded();
  }

  @Override
  public byte[] getDerEncodingWithPK() {
    throw new InternalError(
        "This method is not implemented and there should be no need for it as this class should only be used for legacy reasons ");
  }
}
