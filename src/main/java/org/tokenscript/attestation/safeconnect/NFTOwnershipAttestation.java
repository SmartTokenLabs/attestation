package org.tokenscript.attestation.safeconnect;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.tokenscript.attestation.ERC721Token;
import org.tokenscript.attestation.core.ExceptionUtil;

import java.util.Date;

public class NFTOwnershipAttestation implements OwnershipAttestationInterface {
    private static final Logger logger = LogManager.getLogger(NFTOwnershipAttestation.class);
    public static final int TAG = 0;
    private final byte[] context;
    private final ERC721Token[] tokens;
    private final Date notBefore;
    private final Date notAfter;

    private final AsymmetricKeyParameter subjectPublicKey;

    public NFTOwnershipAttestation(byte[] context, ERC721Token[] tokens, Date notBefore, Date notAfter, AsymmetricKeyParameter subjectPublicKey) {
        this.context = context;
        this.tokens = tokens;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.subjectPublicKey = subjectPublicKey;
    }

    public byte[] getContext() {
        return context;
    }

    public ERC721Token[] getTokens() {
        return tokens;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public AsymmetricKeyParameter getSubjectPublicKey() {
        return subjectPublicKey;
    }

    @Override
    public byte[] getDerEncoding() {
        try {
            ASN1EncodableVector res = new ASN1EncodableVector();
            res.add(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(getSubjectPublicKey()));
            ASN1EncodableVector asn1Tokens = new ASN1EncodableVector();
            for (ERC721Token token : getTokens()) {
                asn1Tokens.add(ASN1Sequence.getInstance(token.getDerEncoding()));
            }
            res.add(new DERSequence(asn1Tokens));
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
    public int getTag() {
        // The tag of address attestation
        return TAG;
    }

    @Override
    public boolean checkValidity() {
        for (ERC721Token current : getTokens()) {
            if (!current.checkValidity()) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean verify() {
        // Always true for the internal NFTOwnershipAttestation
        return true;
    }
}