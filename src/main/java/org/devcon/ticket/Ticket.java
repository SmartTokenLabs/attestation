package org.devcon.ticket;

import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.core.Attestable;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.SignatureUtility;
import org.tokenscript.attestation.core.URLUtility;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class Ticket extends Attestable {
  private static final Logger logger = LogManager.getLogger(Ticket.class);

  private final String ticketId;
  private final int ticketClass;
  private final String devconId;
  private final byte[] commitment;
  private final AlgorithmIdentifier algorithm;
  private final byte[] signature;
  public static final String magicLinkURLPrefix = "https://ticket.devcon.org/";
  private final AsymmetricKeyParameter publicKey;
  private final byte[] encoded;

  public Ticket(String mail, String devconId, BigInteger ticketId, int ticketClass,
      AsymmetricCipherKeyPair keys, BigInteger secret ) {
    this(mail, devconId, ticketId.toString(), ticketClass, keys, secret);
  }

  /**
   *  @param mail The mail address of the recipient
   * @param devconId The id of the conference for which the ticket should be used
   * @param ticketId The Id of the ticket
   * @param ticketClass The type of this ticket
   * @param keys The keys used to sign the ticket
   * @param secret the secret that must be known to cash the cheque
   */
  public Ticket(String mail, String devconId, String ticketId, int ticketClass,
      AsymmetricCipherKeyPair keys, BigInteger secret ) {
    this.ticketId = ticketId;
    this.ticketClass = ticketClass;
    this.devconId = devconId;
    this.commitment = AttestationCrypto.makeCommitment(mail, AttestationType.EMAIL, secret);
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
          keys.getPublic());
      this.algorithm = spki.getAlgorithm();
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not construct spki", e);
    }
    ASN1Sequence asn1Tic = makeTicket();
    try {
      this.signature = SignatureUtility.signWithEthereum(asn1Tic.getEncoded(), keys.getPrivate());
      this.encoded = encodeSignedTicket(asn1Tic);
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode signature", e);
    }
    this.publicKey = keys.getPublic();
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Signature is invalid"));
    }
  }

  public Ticket(String devconId, BigInteger ticketId, int ticketClass, byte[] commitment, byte[] signature, AsymmetricKeyParameter publicKey) {
    this(devconId, ticketId.toString(), ticketClass, commitment, signature, publicKey);
  }

  public Ticket(String devconId, String ticketId, int ticketClass, byte[] commitment, byte[] signature, AsymmetricKeyParameter publicKey) {
    this.ticketId = ticketId;
    this.ticketClass = ticketClass;
    this.devconId = devconId;
    this.commitment = commitment;
    try {
      SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
          publicKey);
      this.algorithm = spki.getAlgorithm();
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode spki", e);
    }
    this.signature = signature;
    ASN1Sequence ticket = makeTicket();
    try {
      this.encoded = encodeSignedTicket(ticket);
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode ticket", e);
    }
    this.publicKey = publicKey;
    if (!verify()) {
      throw ExceptionUtil.throwException(logger, new IllegalArgumentException("Signature is invalid"));
    }
  }

  ASN1Sequence makeTicket() {
    ASN1EncodableVector ticket = new ASN1EncodableVector();
    ticket.add(new DERUTF8String(devconId));
    addTicketId(ticket);
    ticket.add(new ASN1Integer(ticketClass));
    ticket.add(new DEROctetString(commitment));
    return new DERSequence(ticket);
  }

  /**
   * Add TicketId as integer if possible, otherwise add it as string
   */
  protected void addTicketId(ASN1EncodableVector ticket) {
    try {
      BigInteger ticketIdInteger = new BigInteger(ticketId);
      ticket.add(new ASN1Integer(ticketIdInteger));
    } catch (NumberFormatException e) {
      // The ticketID cannot be expressed as an integer
      ticket.add(new DERUTF8String(ticketId));
    }
  }

  protected byte[] encodeSignedTicket(ASN1Sequence ticket) throws IOException {
    ASN1EncodableVector signedTicket = new ASN1EncodableVector();
    signedTicket.add(ticket);
    signedTicket.add(new DERBitString(signature));
    return new DERSequence(signedTicket).getEncoded();
  }

  @Override
  public byte[] getDerEncoding() {
    return encoded;
  }

  public String getUrlEncoding()  {
    return URLUtility.encodeData(getDerEncoding());
  }

  @Override
  public boolean verify() {
    try {
      ASN1Sequence ticket = makeTicket();
      if (!SignatureUtility.verifyEthereumSignature(ticket.getEncoded(), signature, this.publicKey)) {
        logger.error("Could not verify signature");
        return false;
      }
    } catch (IOException e) {
      logger.error("Could not decode signature");
      return false;
    }
    return true;
  }

  @Override
  public boolean checkValidity() {
    // The ticket is always valid on its own. It depends on which conference it is used
    // and whether it has been revoked that decides if it can be used
    return true;
  }

  public String getTicketId() {
    return ticketId;
  }

  public int getTicketClass() {
    return ticketClass;
  }

  public String getDevconId() {
    return devconId;
  }

  public byte[] getCommitment() {
    return commitment;
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
