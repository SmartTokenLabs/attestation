package com.alphawallet.attestation.core;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

public class URLUtility {
  private static final Logger logger = LogManager.getLogger(URLUtility.class);

  public static String encodeList(List<byte[]> inputs) {
    return encodeData(encodeListHelper(inputs));
  }

  private static byte[] encodeListHelper(List<byte[]> inputs) {
    try {
      ASN1EncodableVector vec = new ASN1EncodableVector();
      for (byte[] current : inputs) {
        vec.add(new DEROctetString(current));
      }
      return new DERSequence(vec).getEncoded();
    } catch (IOException e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
    }
  }

  public static String encodeData(byte[] input) {
    return new String(Base64.getUrlEncoder().encode(input), UTF_8);
  }

  /**
   * @param url The part of the URL that contains encoding. I.e. it must be pruned for domainame and such
   */
  public static List<byte[]> decodeList(String url) throws IOException {
    List<byte[]> res = new ArrayList<>();
    byte[] decodedData = decodeData(url);
    ASN1InputStream input = new ASN1InputStream(decodedData);
    ASN1Encodable[] asn1 = ASN1Sequence.getInstance(input.readObject()).toArray();
    for (ASN1Encodable current : asn1) {
      res.add(ASN1OctetString.getInstance(current).getOctets());
    }
    return res;
  }

  public static byte[] decodeData(String url) {
    return Base64.getUrlDecoder().decode(url.getBytes(UTF_8));
  }
}
