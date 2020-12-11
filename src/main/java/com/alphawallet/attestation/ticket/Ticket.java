package com.alphawallet.attestation.ticket;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.ASNEncodable;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.Verifiable;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class Ticket implements ASNEncodable, Verifiable {
  // TODO we need details on this
  public enum TicketClass {
    REGULAR(0),
    VIP(1),
    SPEAKER(2),
    STAFF(3);
    private final int value;

    TicketClass(final int newValue) {
      value = newValue;
    }

    public int getValue() { return value; }
  }

  private final BigInteger ticketId;
  private TicketClass ticketClass = null;
  private final int conferenceId;
  private final byte[] riddle;
  private final AlgorithmIdentifier algorithm;
  private final byte[] signature;

  private final AsymmetricKeyParameter publicKey;
  private final byte[] encoded;

  /**
   *
   * @param mail The mail address of the recipient
   * @param ticketId The Id of the ticket
   * @param ticketClass The type of this ticket
   * @param conferenceId The id of the conference for which the ticket should be used
   * @param keys The keys used to sign the cheque
   * @param secret the secret that must be known to cash the cheque
   */
  public Ticket(String mail, BigInteger ticketId, TicketClass ticketClass, int conferenceId,
      AsymmetricCipherKeyPair keys, BigInteger secret ) {
    AttestationCrypto crypto = new AttestationCrypto(new SecureRandom());
    this.ticketId = ticketId;
    this.ticketClass = ticketClass;
    this.conferenceId = conferenceId;
    this.riddle = crypto.makeRiddle(mail, AttestationType.EMAIL, secret);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
          keys.getPublic());
      this.algorithm = spki.getAlgorithm();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    ASN1Sequence asn1Tic = makeTicket();
    try {
      this.signature = SignatureUtility.sign(asn1Tic.getEncoded(), keys.getPrivate());
      this.encoded = encodeSignedTicket(asn1Tic, algorithm, signature);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    this.publicKey = keys.getPublic();
    if (!verify()) {
      throw new IllegalArgumentException("Public and private keys are incorrect");
    }
  }

  public Ticket(BigInteger ticketId, TicketClass ticketClass, int conferenceId, byte[] riddle, byte[] signature, AsymmetricKeyParameter publicKey) {
    this.ticketId = ticketId;
    this.ticketClass = ticketClass;
    this.conferenceId = conferenceId;
    this.riddle = riddle;
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
          publicKey);
      this.algorithm = spki.getAlgorithm();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    this.signature = signature;
    ASN1Sequence ticket = makeTicket();
    try {
      this.encoded = encodeSignedTicket(ticket, this.algorithm, this.signature);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    this.publicKey = publicKey;
    if (!verify()) {
      throw new IllegalArgumentException("Signature is invalid");
    }
  }

  public Ticket(byte[] derEncoded, AsymmetricKeyParameter publicKey) throws IOException, IllegalArgumentException {
    this.encoded = derEncoded;
    ASN1InputStream input = new ASN1InputStream(derEncoded);
    ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
    ASN1Sequence ticket = ASN1Sequence.getInstance(asn1.getObjectAt(0));
    this.ticketId = (ASN1Integer.getInstance(ticket.getObjectAt(0))).getValue();
    int ticketClassInt = ASN1Integer.getInstance(ticket.getObjectAt(1)).getValue().intValueExact();
    for (TicketClass current : TicketClass.values()) {
      if (current.value == ticketClassInt) {
        this.ticketClass = current;
      }
    }
    if (ticketClass == null) {
      throw new IOException("Not valid ticket class");
    }
    this.conferenceId = (ASN1Integer.getInstance(ticket.getObjectAt(2))).getValue().intValueExact();
    this.riddle = (ASN1OctetString.getInstance(ticket.getObjectAt(3))).getOctets();

    this.algorithm = AlgorithmIdentifier.getInstance(asn1.getObjectAt(1));
    this.publicKey = publicKey;
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
    // Ensure that the right type of public key is given
    if (!Arrays.equals(spki.getAlgorithm().getEncoded(), algorithm.getEncoded())) {
      throw new IllegalArgumentException("The public key is not of the same type as used to sign the ticket");
    }

    // Verify signature
    this.signature = DERBitString.getInstance(asn1.getObjectAt(2)).getBytes();
    if (!verify()) {
      throw new IllegalArgumentException("Signature is invalid");
    }
  }

  private ASN1Sequence makeTicket() {
    ASN1EncodableVector ticket = new ASN1EncodableVector();
    ticket.add(new ASN1Integer(ticketId));
    ticket.add(new ASN1Integer(ticketClass.getValue()));
    ticket.add(new ASN1Integer(conferenceId));
    ticket.add(new DEROctetString(riddle));
    return new DERSequence(ticket);
  }

  private byte[] encodeSignedTicket(ASN1Sequence ticket, AlgorithmIdentifier algorithm, byte[] signature) throws IOException {
    ASN1EncodableVector signedTicket = new ASN1EncodableVector();
    signedTicket.add(ticket);
    signedTicket.add(algorithm);
    signedTicket.add(new DERBitString(signature));
    return new DERSequence(signedTicket).getEncoded();
  }

  @Override
  public byte[] getDerEncoding() {
    return encoded;
  }

  @Override
  public boolean verify() {
    try {
      ASN1Sequence ticket = makeTicket();
      return SignatureUtility.verify(ticket.getEncoded(), signature, this.publicKey);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public BigInteger getTicketId() {
    return ticketId;
  }

  public TicketClass getTicketClass() {
    return ticketClass;
  }

  public int getConferenceId() {
    return conferenceId;
  }

  public byte[] getRiddle() {
    return riddle;
  }

  public AlgorithmIdentifier getAlgorithm() {
    return algorithm;
  }

  public byte[] getSignature() {
    return signature;
  }

  public AsymmetricKeyParameter getPublicKey() {
    return publicKey;
  }
}
