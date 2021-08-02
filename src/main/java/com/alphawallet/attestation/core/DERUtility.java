package com.alphawallet.attestation.core;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
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

public class DERUtility {
  private static final Logger logger = LogManager.getLogger(DERUtility.class);
  public static final Base64.Encoder rfc1421Encoder = Base64.getMimeEncoder(64, new byte[] {'\n'});

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
      throw ExceptionUtil.makeRuntimeException(logger, "Could not restore keys", e);
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
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
    }
  }

  public static BigInteger decodeSecret(byte[] secretBytes) {
    try {
      ASN1InputStream input = new ASN1InputStream(secretBytes);
      ASN1Sequence asn1 = ASN1Sequence.getInstance(input.readObject());
      ASN1OctetString secret = ASN1OctetString.getInstance(asn1.getObjectAt(0));
      return new BigInteger(secret.getOctets());
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not decode asn1", e);
    }
  }

  /**
   * Restores bytes from a base64 PEM-style DER encoding
   * @param lines The string list containing the base64 encoding
   * @return the raw DER bytes that are encoded
   */
  public static byte[] restoreBytes(List<String> lines) {
    // skip first and last line
    String longStr = String.join("", lines.subList(1, lines.size()-1));
    return Base64.getDecoder().decode(longStr.getBytes(StandardCharsets.UTF_8));
  }

  public static void writePEM(byte[] input, String type, OutputStream out) throws IOException {
    out.write(("-----BEGIN " + type + "-----\n").getBytes(StandardCharsets.UTF_8));
    out.write(rfc1421Encoder.encode(input));
    out.write(("\n-----END " + type + "-----\n").getBytes(StandardCharsets.UTF_8));
  }

  public static void writePEM(byte[] input, String type, Path file) throws IOException {
    OutputStream out = Files.newOutputStream(file);
    writePEM(input, type, out);
    out.close();
  }
}
