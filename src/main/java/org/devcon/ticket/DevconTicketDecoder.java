package org.devcon.ticket;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.SignatureUtility;

public class DevconTicketDecoder implements ObjectDecoder<Ticket> {
  private static final Logger logger = LogManager.getLogger(DevconTicketDecoder.class);
  private static final String DEFAULT = "default";

  private Map<String, AsymmetricKeyParameter> idsToKeys;

  public DevconTicketDecoder(Map<String, AsymmetricKeyParameter> idsToKeys) {
    if (idsToKeys.containsKey(DEFAULT)) {
      throw new IllegalArgumentException("A conference cannot be called " + DEFAULT);
    }
    this.idsToKeys = idsToKeys;
  }

  public DevconTicketDecoder(AsymmetricKeyParameter publicKey) {
    this();
    idsToKeys.put(DEFAULT, publicKey);
  }

  public DevconTicketDecoder() {
    idsToKeys = new HashMap<>();
  }

  @Override
  public Ticket decode(byte[] encoding) throws IOException {
    ASN1InputStream input = null;
    try {
      input = new ASN1InputStream(encoding);
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      input.close();
      ASN1Sequence ticket = ASN1Sequence.getInstance(asn1.getObjectAt(0));
      String devconId = (ASN1UTF8String.getInstance(ticket.getObjectAt(0))).getString();
      ASN1Primitive ticketIdObj = ticket.getObjectAt(1).toASN1Primitive();
      String ticketId;
      if (ticketIdObj instanceof ASN1Integer) {
        ticketId = (ASN1Integer.getInstance(ticket.getObjectAt(1))).getValue().toString();
      } else { // ASN1UTF8String
        ticketId = (ASN1UTF8String.getInstance(ticket.getObjectAt(1))).getString();
      }
      int ticketClassInt = ASN1Integer.getInstance(ticket.getObjectAt(2)).getValue().intValueExact();
      byte[] commitment = (ASN1OctetString.getInstance(ticket.getObjectAt(3))).getOctets();
      /* refactored 2021-01-05 : we don't care about the ticket class set on our level
      TicketClass ticketClass = null;
      for (TicketClass current : TicketClass.values()) {
        if (current.getValue() == ticketClassInt) {
          ticketClass = current;
        }
      }
      if (ticketClass == null) {
        throw new IOException("Not valid ticket class");
      }
     */
      byte[] signature = ASN1BitString.getInstance(asn1.getObjectAt(1)).getBytes();
      return new Ticket(devconId, ticketId, ticketClassInt, commitment, signature, getPk(devconId));
    } finally {
      input.close();
    }
  }

  AsymmetricKeyParameter getPk(String devconId) {
    AsymmetricKeyParameter pk;
    // First try to get the key using devconID
    pk = idsToKeys.get(devconId);
    if (pk == null && idsToKeys.size() == 1) {
      // otherwise use default
      pk = idsToKeys.get(DEFAULT);
    }
    if (pk != null) {
      return pk;
    }
    ExceptionUtil.throwException(logger, new IllegalArgumentException("Conference ID " + devconId + ", does not match any associated PK"));
    return null;
  }
}
