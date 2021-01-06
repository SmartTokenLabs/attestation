package com.alphawallet.attestation.core;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64Encoder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class DERUtility {
  public static final int CHARS_IN_LINE = 65;

  /**
   * Extact an EC keypair from the DER encoded private key
   * @param input The DER encoded input
   * @return
   */
  public static AsymmetricCipherKeyPair restoreBase64Keys(List<String> input) {
    try {
      ECPrivateKeyParameters priv = (ECPrivateKeyParameters)
          PrivateKeyFactory.createKey(restoreBytes(input));
      ECPoint Q = priv.getParameters().getG().multiply(priv.getD());
      ECKeyParameters pub = new ECPublicKeyParameters(Q, priv.getParameters());
      return new AsymmetricCipherKeyPair(pub, priv);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Converts ASNPrimitive data in RFC5915 format to a keypair.
   * Ideally, in production environment keys shouldn't be in RFC5915 key distribution format,
   * but rather in PKCS#8 format so that it can be encrypted.
   * @param data
   * @return
   */
  public static AsymmetricCipherKeyPair restoreRFC5915Key(ASN1Primitive data) {
    ECPrivateKey pKey = ECPrivateKey.getInstance(data);
    BigInteger d = pKey.getKey();
    ASN1Primitive p = pKey.getParameters();
    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) pKey.getParameters();

    X9ECParameters x9 = CustomNamedCurves.getByOID(oid);
    if (x9 == null) {
      x9 = ECNamedCurveTable.getByOID(oid);
    }
    ECNamedDomainParameters dParams = new ECNamedDomainParameters(
            oid, x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
    ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(d, dParams);
    ECPoint q = privateKey.getParameters().getG().multiply(d);
    ECKeyParameters pub = new ECPublicKeyParameters(q, privateKey.getParameters());
    return new AsymmetricCipherKeyPair(pub, privateKey);
  }

  public static byte[] encodeSecret(BigInteger secret) {
    try {
      ASN1EncodableVector asn1 = new ASN1EncodableVector();
      asn1.add(new DEROctetString(secret.toByteArray()));
      return new DERSequence(asn1).getEncoded();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static BigInteger decodeSecret(byte[] secretBytes) {
    try {
      ASN1InputStream input = new ASN1InputStream(secretBytes);
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      ASN1OctetString secret = ASN1OctetString.getInstance(asn1.getObjectAt(0));
      return new BigInteger(secret.getOctets());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Restores bytes from a base64 PEM-style DER encoding
   * @param input The string containing the base64 encoding
   * @return the raw DER bytes that are encoded
   */
  public static byte[] restoreBytes(List<String> lines) throws IOException {
    // skip first and last line
    List<String> arr = lines.subList(1, lines.size()-1);
    StringBuffer buf = new StringBuffer();
    for (int i = 0; i < arr.size(); i++) {
      buf.append(arr.get(i));
    }
    Base64Encoder coder = new Base64Encoder();
    ByteArrayOutputStream outstream = new ByteArrayOutputStream();
    coder.decode(buf.toString(), outstream);
    return outstream.toByteArray();
  }

  public static String printDER(byte[] input, String type) {
    try {
      Base64Encoder coder = new Base64Encoder();
      ByteArrayOutputStream outstream = new ByteArrayOutputStream();
      coder.encode(input, 0, input.length, outstream);
      byte[] encodedCert = outstream.toByteArray();
      StringBuilder builder = new StringBuilder();
      builder.append("-----BEGIN " + type + "-----\n");
      addBytes(builder, encodedCert);
      builder.append("-----END " + type + "-----");
      return builder.toString();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static void addBytes(StringBuilder builder, byte[] encoding) {
    int start = 0;
    while (start < encoding.length) {
      int end = encoding.length - (start + CHARS_IN_LINE) > 0 ?
          start + CHARS_IN_LINE : encoding.length;
      builder.append(new String(Arrays.copyOfRange(encoding, start, end)));
      builder.append('\n');
      start += CHARS_IN_LINE;
    }
  }
}
