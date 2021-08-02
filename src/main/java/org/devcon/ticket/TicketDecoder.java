package org.devcon.ticket;

import com.alphawallet.attestation.AttestableObjectDecoder;
import com.alphawallet.attestation.core.ExceptionUtil;
import com.alphawallet.attestation.core.SignatureUtility;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class TicketDecoder implements AttestableObjectDecoder<Ticket> {
  private static final Logger logger = LogManager.getLogger(TicketDecoder.class);

  private AsymmetricKeyParameter publicKey;

  public TicketDecoder(AsymmetricKeyParameter publicKey) {
    this.publicKey = publicKey;
  }

  public TicketDecoder() {
    publicKey = null;
  }

  @Override
  public Ticket decode(byte[] encoding) throws IOException {
    ASN1InputStream input = new ASN1InputStream(encoding);
    ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
    ASN1Sequence ticket = ASN1Sequence.getInstance(asn1.getObjectAt(0));
    String devconId = (DERUTF8String.getInstance(ticket.getObjectAt(0))).getString();
    BigInteger ticketId = (ASN1Integer.getInstance(ticket.getObjectAt(1))).getValue();
    int ticketClassInt = ASN1Integer.getInstance(ticket.getObjectAt(2)).getValue().intValueExact();
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
    byte[] commitment = (ASN1OctetString.getInstance(asn1.getObjectAt(1))).getOctets();
    byte[] signature = parsePKandSignature(asn1);
    return new Ticket(devconId, ticketId, ticketClassInt, commitment, signature, publicKey);
  }

  /**
   * Returns the signature and ensures that the optional public key is properly restored
   * @param input The encoded Ticket
   * @return
   */
  private byte[] parsePKandSignature(ASN1Sequence input) throws IOException, IllegalArgumentException{
    byte[] signature;
    ASN1Encodable object = input.getObjectAt(2);
    if (object instanceof ASN1Sequence) {
      // The optional PublicKeyInfo is included
      parseEncodingOfPKInfo((ASN1Sequence) object);
      signature = DERBitString.getInstance(input.getObjectAt(3)).getBytes();
    } else if (object instanceof DERBitString) {
      // Only the signature is included
      signature = DERBitString.getInstance(input.getObjectAt(2)).getBytes();
    } else {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Invalid ticket encoding"));
    }
    return signature;
  }

  private void parseEncodingOfPKInfo(ASN1Sequence publicKeyInfo) throws IOException, IllegalArgumentException {
    AlgorithmIdentifier algorithm = AlgorithmIdentifier.getInstance(publicKeyInfo.getObjectAt(0));
    byte[] publicKeyBytes = DERBitString.getInstance(publicKeyInfo.getObjectAt(1)).getEncoded();
    AsymmetricKeyParameter decodedPublicKey = SignatureUtility.restoreDefaultKey(algorithm, publicKeyBytes);
      SubjectPublicKeyInfo decodedSpki = SubjectPublicKeyInfoFactory
          .createSubjectPublicKeyInfo(decodedPublicKey);
    // Ensure that the right type of public key is given
    if (publicKey != null) {
      SubjectPublicKeyInfo referenceSpki = SubjectPublicKeyInfoFactory
          .createSubjectPublicKeyInfo(publicKey);
      if (!Arrays.equals(referenceSpki.getEncoded(), decodedSpki.getEncoded())) {
        throw ExceptionUtil.throwException(logger, new IllegalArgumentException(
            "The public key is not of the same as supplied as argument"));
      }
    }
    publicKey = decodedPublicKey;
  }
}
