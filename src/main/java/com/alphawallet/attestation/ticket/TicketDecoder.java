package com.alphawallet.attestation.ticket;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.ticket.Ticket.TicketClass;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class TicketDecoder implements AttestableObjectDecoder<Ticket> {
  private final AsymmetricKeyParameter publicKey;

  public TicketDecoder(AsymmetricKeyParameter publicKey) {
    this.publicKey = publicKey;
  }
  
  @Override
  public Ticket decode(byte[] encoding) throws IOException {
    ASN1InputStream input = new ASN1InputStream(encoding);
    ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
    ASN1Sequence ticket = ASN1Sequence.getInstance(asn1.getObjectAt(0));
    int devconId = (ASN1Integer.getInstance(ticket.getObjectAt(0))).getValue().intValueExact();
    BigInteger ticketId = (ASN1Integer.getInstance(ticket.getObjectAt(1))).getValue();
    int ticketClassInt = ASN1Integer.getInstance(ticket.getObjectAt(2)).getValue().intValueExact();
    TicketClass ticketClass = null;
    for (TicketClass current : TicketClass.values()) {
      if (current.getValue() == ticketClassInt) {
        ticketClass = current;
      }
    }
    if (ticketClass == null) {
      throw new IOException("Not valid ticket class");
    }
    byte[] riddle = (ASN1OctetString.getInstance(ticket.getObjectAt(3))).getOctets();

    AlgorithmIdentifier algorithm = AlgorithmIdentifier.getInstance(asn1.getObjectAt(1));
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
    // Ensure that the right type of public key is given
    if (!Arrays.equals(spki.getAlgorithm().getEncoded(), algorithm.getEncoded())) {
      throw new IllegalArgumentException("The public key is not of the same type as used to sign the ticket");
    }

    // Verify signature
    byte[] signature = DERBitString.getInstance(asn1.getObjectAt(2)).getBytes();
    return new Ticket(devconId, ticketId, ticketClass, riddle, signature, publicKey);
  }
}
