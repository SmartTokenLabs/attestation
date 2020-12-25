package com.alphawallet.attestation.ticket;

import com.alphawallet.attestation.IdentifierAttestation.AttestationType;
import com.alphawallet.attestation.core.Attestable;
import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class Ticket implements Attestable {

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
  private final int devconId;
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
   * @param devconId The id of the conference for which the ticket should be used
   * @param keys The keys used to sign the cheque
   * @param secret the secret that must be known to cash the cheque
   */
  public Ticket(String mail, int devconId, BigInteger ticketId, TicketClass ticketClass,
      AsymmetricCipherKeyPair keys, BigInteger secret ) {
    AttestationCrypto crypto = new AttestationCrypto(new SecureRandom());
    this.ticketId = ticketId;
    this.ticketClass = ticketClass;
    this.devconId = devconId;
    this.riddle = crypto.makeCommitment(mail, AttestationType.EMAIL, secret);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
          keys.getPublic());
      this.algorithm = spki.getAlgorithm();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    ASN1Sequence asn1Tic = makeTicket();
    try {
      this.signature = SignatureUtility.signDeterministic(asn1Tic.getEncoded(), keys.getPrivate());
      this.encoded = encodeSignedTicket(asn1Tic, algorithm, signature);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    this.publicKey = keys.getPublic();
    if (!verify()) {
      throw new IllegalArgumentException("Public and private keys are incorrect");
    }
  }

  public Ticket(int devconId, BigInteger ticketId, TicketClass ticketClass, byte[] riddle, byte[] signature, AsymmetricKeyParameter publicKey) {
    this.ticketId = ticketId;
    this.ticketClass = ticketClass;
    this.devconId = devconId;
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

  private ASN1Sequence makeTicket() {
    ASN1EncodableVector ticket = new ASN1EncodableVector();
    ticket.add(new ASN1Integer(devconId));
    ticket.add(new ASN1Integer(ticketId));
    ticket.add(new ASN1Integer(ticketClass.getValue()));
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

  @Override
  public boolean checkValidity() {
    // The ticket is always valid on its own. It depends on which conference it is used
    // and whether it has been revoked that decides if it can be used
    return true;
  }

  public BigInteger getTicketId() {
    return ticketId;
  }

  public TicketClass getTicketClass() {
    return ticketClass;
  }

  public int getDevconId() {
    return devconId;
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
