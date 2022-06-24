package org.tokenscript.attestation.safeconnect;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.encoders.Hex;
import org.tokenscript.attestation.ERC721Token;
import org.tokenscript.attestation.core.ExceptionUtil;

import java.util.Date;

public class EthereumAddressAttestation implements SignedOwnershipAttestationInterface {
    private static final Logger logger = LogManager.getLogger(NFTOwnershipAttestation.class);
    private final byte[] context;
    private final String subjectAddress;
    private final Date notBefore;
    private final Date notAfter;
    private final AsymmetricKeyParameter subjectPublicKey;

    public EthereumAddressAttestation(byte[] context, String subjectAddress, Date notBefore, Date notAfter, AsymmetricKeyParameter subjectPublicKey) {
        this.context = context;
        this.subjectAddress = subjectAddress;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.subjectPublicKey = subjectPublicKey;
    }

    public byte[] getContext() {
        return context;
    }

    public String getSubjectAddress() {
        return subjectAddress;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    @Override
    public AsymmetricKeyParameter getVerificationKey() {
        return null;
    }

    public AsymmetricKeyParameter getSubjectPublicKey() {
        return subjectPublicKey;
    }

    @Override
    public byte[] getDerEncoding() {
        try {
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(getSubjectPublicKey()));
            // Start at index 2 to remove "0x"
            res.add(new DEROctetString(Hex.decode(subjectAddress.substring(2))));
            ASN1EncodableVector validity = new ASN1EncodableVector();
            validity.add(new ASN1Integer(getNotBefore().toInstant().getEpochSecond()));
            validity.add(new ASN1Integer(getNotAfter().toInstant().getEpochSecond()));
            res.add(new DERSequence(validity));
            if (getContext() != null) {
                res.add(new DEROctetString(getContext()));
            }
            return new DERSequence(res).getEncoded();
        } catch (Exception e) {
            throw ExceptionUtil.makeRuntimeException(logger, "Could not encode asn1", e);
        }
    }

    @Override
    public boolean checkValidity() {
        try {
            ERC721Token.validateAddress(subjectAddress);
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    @Override
    public boolean verify() {
        // Always true for the internal EthereumAddressAttestation
        return true;
    }
}
