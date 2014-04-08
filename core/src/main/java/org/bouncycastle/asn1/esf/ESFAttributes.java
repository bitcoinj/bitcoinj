package org.bouncycastle.asn1.esf;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public interface ESFAttributes
{
    public static final ASN1ObjectIdentifier  sigPolicyId = PKCSObjectIdentifiers.id_aa_ets_sigPolicyId;
    public static final ASN1ObjectIdentifier  commitmentType = PKCSObjectIdentifiers.id_aa_ets_commitmentType;
    public static final ASN1ObjectIdentifier  signerLocation = PKCSObjectIdentifiers.id_aa_ets_signerLocation;
    public static final ASN1ObjectIdentifier  signerAttr = PKCSObjectIdentifiers.id_aa_ets_signerAttr;
    public static final ASN1ObjectIdentifier  otherSigCert = PKCSObjectIdentifiers.id_aa_ets_otherSigCert;
    public static final ASN1ObjectIdentifier  contentTimestamp = PKCSObjectIdentifiers.id_aa_ets_contentTimestamp;
    public static final ASN1ObjectIdentifier  certificateRefs = PKCSObjectIdentifiers.id_aa_ets_certificateRefs;
    public static final ASN1ObjectIdentifier  revocationRefs = PKCSObjectIdentifiers.id_aa_ets_revocationRefs;
    public static final ASN1ObjectIdentifier  certValues = PKCSObjectIdentifiers.id_aa_ets_certValues;
    public static final ASN1ObjectIdentifier  revocationValues = PKCSObjectIdentifiers.id_aa_ets_revocationValues;
    public static final ASN1ObjectIdentifier  escTimeStamp = PKCSObjectIdentifiers.id_aa_ets_escTimeStamp;
    public static final ASN1ObjectIdentifier  certCRLTimestamp = PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp;
    public static final ASN1ObjectIdentifier  archiveTimestamp = PKCSObjectIdentifiers.id_aa_ets_archiveTimestamp;
    public static final ASN1ObjectIdentifier  archiveTimestampV2 = PKCSObjectIdentifiers.id_aa.branch("48");
}
