package org.devcon.ticket;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Proof of concept Ticket system for Liscon.
 * It is significantly less secure than the regular Ticket format and should only be used in legacy settings!
 */
@Deprecated
public class LisconTicketDecoder extends DevconTicketDecoder {
  public LisconTicketDecoder(AsymmetricKeyParameter publicKey) {
    super(publicKey);
  }

  @Override
  public Ticket decode(byte[] encoding) throws IOException {
    ASN1InputStream input = new ASN1InputStream(encoding);
    ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
    ASN1Sequence ticket = ASN1Sequence.getInstance(asn1.getObjectAt(0));
    String devconId = (DERUTF8String.getInstance(ticket.getObjectAt(0))).getString();
    BigInteger ticketId = (ASN1Integer.getInstance(ticket.getObjectAt(1))).getValue();
    int ticketClassInt = ASN1Integer.getInstance(ticket.getObjectAt(2)).getValue().intValueExact();

    byte[] commitment = (ASN1OctetString.getInstance(asn1.getObjectAt(1))).getOctets();
    byte[] signature = ASN1BitString.getInstance(asn1.getObjectAt(2)).getBytes();
    return new LisconTicket(devconId, ticketId, ticketClassInt, commitment, signature, getPk(devconId));
  }
}
