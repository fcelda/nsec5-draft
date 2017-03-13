---
title: NSEC5, DNSSEC Authenticated Denial of Existence
abbrev: NSEC5
docname: draft-vcelak-nsec5-05
date: 2017

ipr: trust200902
area: Internet
wg: Network Working Group
kw: Internet-Draft
cat: std

coding: us-ascii
pi:
  - toc
  - symrefs
  - sortrefs
  - compact
  - rfcedstyle
  - comments
  - inline

author:
  -
    ins: J. Vcelak
    name: Jan Vcelak
    org: CZ.NIC
    street: Milesovska 1136/5
    city: Praha
    code: 130 00
    country: CZ
    email: jan.vcelak@nic.cz
  -
    ins: S. Goldberg
    name: Sharon Goldberg
    org: Boston University
    street: 111 Cummington St, MCS135
    city: Boston
    region: MA
    code: '02215'
    country: USA
    email: goldbe@cs.bu.edu
  -
    ins: D. Papadopoulos
    name: Dimitrios Papadopoulos
    org: University of Maryland
    street: 8223 Paint Branch Dr
    city: College Park
    region: MD
    code: '20740'
    country: USA
    email: dipapado@umd.edu
  -
    ins: S. Huque
    name: Shumon Huque
    org: Salesforce
    street: 2550 Wasser Terr
    city: Herndon
    region: VA
    code: '20171'
    country: USA
    email: shuque@gmail.com
  -
    ins: D. C. Lawrence
    name: David C Lawrence
    org: Akamai Technologies
    street: 150 Broadway
    city: Boston
    region: MA
    code: 02142-1054
    country: USA
    email: tale@akamai.com

normative:
  rfc1034: 
  rfc1035: 
  rfc2119: 
  rfc2136: 
  rfc2181: 
  rfc2308: 
  rfc4033: 
  rfc4034: 
  rfc4035: 
  rfc4648: 
  rfc5114: 
  rfc5155: 
  rfc6234: 
  rfc6605: 
  rfc7748: 
  rfc8080: 
  I-D.goldbe-vrf:
  FIPS-186-3:
    title: Digital Signature Standard (DSS)
    author:
      org: National Institute for Standards and Technology
    date: 2009-06
    seriesinfo:
      FIPS: PUB 186-3

informative:
  rfc6781: 
  rfc7129: 
  rfc7719: 
  I-D.gieben-nsec4: 
  nsec5:
    target: https://eprint.iacr.org/2014/582.pdf
    title: 'NSEC5: Provably Preventing DNSSEC Zone Enumeration'
    author:
    - ins: S. Goldberg
    - ins: M. Naor
    - ins: D. Papadopoulos
    - ins: L. Reyzin
    - ins: S. Vasant
    - ins: A. Ziv
    date: 2014-07
    seriesinfo:
      in: NDSS'15
  nsec5ecc:
    target: https://eprint.iacr.org/2017/099.pdf
    title: Can NSEC5 be Practical for DNSSEC Deployments?
    author:
    - ins: D. Papadopoulos
    - ins: D. Wessels
    - ins: S. Huque
    - ins: J. Vcelak
    - ins: M. Naor
    - ins: L. Reyzin
    - ins: S. Goldberg
    date: 2017-02
    seriesinfo:
      in: ePrint Cryptology Archive 2017/099
  nsec3gpu:
    title: GPU-Based NSEC3 Hash Breaking
    author:
    - ins: M. Wander
    - ins: L. Schwittmann
    - ins: C. Boelmann
    - ins: T. Weis
    date: 2014
    seriesinfo:
      in: IEEE Symp. Network Computing and Applications (NCA)
  nsec3walker:
    target: http://dnscurve.org/nsec3walker.html
    title: Nsec3 walker
    author:
    - ins: D.  J. Bernstein
    date: 2011
  nmap-nsec-enum:
    target: https://nmap.org/nsedoc/scripts/dns-nsec-enum.html
    title: 'nmap: dns-nsec-enum'
    author:
    - ins: J.  R. Bond
    date: 2011
  nmap-nsec3-enum:
    target: https://nmap.org/nsedoc/scripts/dns-nsec3-enum.html
    title: 'nmap: dns-nsec3-enum'
    author:
    - ins: A. Nikolic
    - ins: J.  R. Bond
    date: 2011
  nsec3map:
    target: https://github.com/anonion0/nsec3map.
    title: nsec3map with John the Ripper plugin
    author:
    - org: anonion0
    date: 2015
  ldns-walk:
    target: http://git.nlnetlabs.nl/ldns/tree/examples/ldns-walk.c
    title: ldns
    author:
    - org: NLNetLabs
    date: 2015
  MRV99:
    title: Verifiable Random Functions
    author:
    - ins: S. Michali
    - ins: M. Rabin
    - ins: S. Vadhan
    date: 1999
    seriesinfo:
      in: FOCS

--- abstract

The Domain Name System Security Extensions (DNSSEC) introduced the
NSEC resource record (RR) for authenticated denial of existence and
the NSEC3 RR for hashed authenticated denial of existence.  This
document introduces NSEC5 as an alternative mechanism for DNSSEC
authenticated denial of existence.  NSEC5 uses verifiable random
functions (VRFs) to prevent offline enumeration of zone
contents. NSEC5 also protects the integrity of the zone contents even
if an adversary compromises one of the authoritative servers for the
zone.  Integrity is preserved because NSEC5 does not require private
zone-signing keys to be present on all authoritative servers for the
zone, in contrast to DNSSEC online signing schemes like NSEC3 White
Lies.

--- note_Ed_note

Text inside square brackets (\[]) is additional background
information, answers to frequently asked questions, general musings,
etc.  They will be removed before publication.  This document is being
collaborated on in GitHub at
\<https://github.com/fcelda/nsec5-draft\>.  The most recent version of
the document, open issues, etc should all be available here.  The
authors gratefully accept pull requests.

--- middle

# Introduction

## Rationale

NSEC5 provides an alternative mechanism for authenticated denial of
existence for the DNS Security Extensions (DNSSEC). NSEC5 has two key
security properties.  First, NSEC5 protects the integrity of the zone
contents even if an adversary compromises one of the authoritative
servers for the zone.  Second, NSEC5 prevents offline zone
enumeration, where an adversary makes a small number of online DNS
queries and then processes them offline in order to learn all of the
names in a zone. Zone enumeration can be used to identify routers,
servers or other "things" that could then be targeted in more complex
attacks. An enumerated zone can also be a source of probable email
addresses for spam, or as a "key for multiple WHOIS queries to reveal
registrant data that many registries may have legal obligations to
protect" {{RFC5155}}.

All other DNSSEC mechanisms for authenticated denial of existence
either fail to preserve integrity against a compromised server, or
fail to prevent offline zone enumeration.

When offline signing with NSEC is used {{RFC4034}}, an NSEC chain of
all existing domain names in the zone is constructed and signed
offline. The chain is made of resource records (RRs), where each RR
represents two consecutive domain names in canonical order present in
the zone.  The authoritative server proves the non-existence of a name
by presenting a signed NSEC RR which covers the name.  Because the
authoritative server does not need not to know the private
zone-signing key, the integrity of the zone is protected even if the
server is compromised.  However, the NSEC chain allows for easy zone
enumeration: N queries to the server suffice to learn all N names in
the zone (see e.g., {{nmap-nsec-enum}}, {{nsec3map}}, and
{{ldns-walk}}).

When offline signing with NSEC3 is used {{RFC5155}}, the original
names in the NSEC chain are replaced by their cryptographic
hashes. Offline signing ensures that NSEC3 preserves integrity even if
an authoritative server is compromised. However, offline zone
enumeration is still possible with NSEC3 (see e.g., {{nsec3walker}},
{{nsec3gpu}}), and is part of standard network reconnaissance tools
(e.g., {{nmap-nsec3-enum}}, {{nsec3map}}).

When online signing is used, the authoritative server holds the
private zone-signing key and uses this key to synthesize NSEC or NSEC3
responses on the fly (e.g.  NSEC3 White Lies (NSEC3-WL) or
Minimally-Covering NSEC, both described in {{RFC7129}}).  Because the
synthesized response only contains information about the queried name
(but not about any other name in the zone), offline zone enumeration
is not possible.  However, because the authoritative server holds the
private zone-signing key, integrity is lost if the authoritative
server is compromised.

| Scheme   | Integrity vs network attacks? | Integrity vs compromised auth. server? | Prevents offline zone enumeration? | Online crypto? |
| Unsigned | NO  | NO  | YES | NO  |
| NSEC     | YES | YES | NO  | NO  |
| NSEC3    | YES | YES | NO  | NO  |
| NSEC3-WL | YES | NO  | YES | YES |
| NSEC5    | YES | YES | YES | YES |
{: cols='l r r r r'}

NSEC5 prevents offline zone enumeration and also protects integrity
even if a zone's authoritative server is compromised.  To do this,
NSEC5 replaces the unkeyed cryptographic hash function used in NSEC3
with a verifiable random function (VRF) {{MRV99}}.  A VRF is the
public-key version of a keyed cryptographic hash.  Only the holder of
the private VRF key can compute the hash, but anyone with public VRF
key can verify the correctness of the hash.

The public VRF key is distributed in an NSEC5KEY RR, similar to a
DNSKEY RR, and is used to verify NSEC5 hash values.  The private VRF
key is present on all authoritative servers for the zone, and is used
to compute hash values. For every query that elicits a negative
response, the authoritative server hashes the query on the fly using
the private VRF key, and also returns the corresponding precomputed
NSEC5 record(s). In contrast to the online signing approach
{{RFC7129}}, the private key that is present on all authoritative
servers for NSEC5 cannot be used to modify the zone contents.

Like online signing approaches, NSEC5 requires the authoritative
server to perform online public key cryptographic operations for every
query eliciting a denying response.  This is necessary; {{nsec5}}
proved that online cryptography is required to prevent offline zone
enumeration while still protecting the integrity of zone contents
against network attacks.

NSEC5 is not intended to replace NSEC or NSEC3. It is an alternative
mechanism for authenticated denial of existence.  This document
specifies NSEC5 based on the FIPS 186-3 P-256 elliptic curve and on
the Ed25519 elliptic curve. A formal cryptographic proof of security
for elliptic curve (EC) NSEC5 is in {{nsec5ecc}}.

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

## Terminology

The reader is assumed to be familiar with the basic DNS and DNSSEC
concepts described in {{RFC1034}}, {{RFC1035}}, {{RFC4033}},
{{RFC4034}}, and {{RFC4035}}; subsequent RFCs that update them in
{{RFC2136}}, {{RFC2181}}, {{RFC2308}}, {{RFC5155}}, and {{RFC7129}};
and DNS terms in {{RFC7719}}.

The reader should also be familiar with verifiable random functions (VRFs)
as defined in {{I-D.goldbe-vrf}}.

The following terminology is used through this document:

Base32hex:
: The "Base 32 Encoding with Extended Hex Alphabet" as specified
  in {{RFC4648}}. The padding characters ("=") are not
  used in the NSEC5 specification.

Base64:
: The "Base 64 Encoding" as specified in {{RFC4648}}.

QNAME:
: The domain name being queried (query name).

Private NSEC5 key:
: The private key for the verifiable random function (VRF).

Public NSEC5 key:
: The public key for the VRF.

NSEC5 proof:
: A VRF proof. The holder of
  the private NSEC5 key (e.g., authoritative server) can
  compute the NSEC5 proof for an input domain name.
  Anyone who knows the public VRF key can verify
  that the NSEC5 proof corresponds to the input domain name.

NSEC5 hash:
: A cryptographic digest of an NSEC5 proof. If the NSEC5
  proof is known, anyone can compute its corresponding NSEC5 hash.

NSEC5 algorithm:
: A triple of VRF algorithms that 
    compute an NSEC5 proof (VRF_prove),
    verify an NSEC5 proof (VRF_verify), 
    and process an NSEC5 proof to obtain its NSEC5 hash (VRF_proof2hash).

# Backward Compatibility

The specification describes a protocol change that is not backward
compatible with {{RFC4035}} and {{RFC5155}}. An NSEC5-unaware resolver
will fail to validate responses introduced by this document.

To prevent NSEC5-unaware resolvers from attempting to validate the
responses, new DNSSEC algorithms identifiers are introduced in
{{iana_considerations}} which alias existing algorithm numbers. The
zones signed according to this specification MUST use only these
algorithm identifiers, thus NSEC5-unaware resolvers will treat the
zone as insecure.

# How NSEC5 Works

With NSEC5, the original domain name is hashed using a VRF {{I-D.goldbe-vrf}}
using the following steps:

1. The domain name is processed using a VRF keyed with the private
  NSEC5 key to obtain the NSEC5 proof.  Anyone who knows the public
  NSEC5 key, normally acquired via an NSEC5KEY RR, can verify that a
  given NSEC5 proof corresponds to a given domain name.

2. The NSEC5 proof is then processed using a publicly-computable VRF
  proof-to-hash function to obtain the NSEC5 hash.  The NSEC5 hash can
  be computed by anyone who knows the input NSEC5 proof.

The NSEC5 hash determines the position of a domain name in an NSEC5
chain.

To sign a zone, the private NSEC5 key is used to compute the NSEC5
hashes for each name in the zone. These NSEC5 hashes are sorted in
canonical order {{RFC4034}}, and each consecutive pair forms an NSEC5
RR.  Each NSEC5 RR is signed offline using the private zone-signing
key.  The resulting signed chain of NSEC5 RRs is provided to all
authoritative servers for the zone, along with the private NSEC5 key.

To prove non-existence of a particular domain name in response to a
query, the server uses the private NSEC5 key to compute the NSEC5
proof and NSEC5 hash corresponding to the queried name.  The server
then identifies the NSEC5 RR that covers the NSEC5 hash, and responds
with this NSEC5 RR and its corresponding RRSIG signature RRset, as
well as a synthesized NSEC5PROOF RR that contains the NSEC5 proof
corresponding to the queried name.

To validate the response, the client verifies the following items:

* The client uses the public NSEC5 key, normally acquired from the
  NSEC5KEY RR, to verify that the NSEC5 proof in the NSEC5PROOF RR
  corresponds to the queried name.

* The client uses the VRF proof-to-hash function to compute the NSEC5
  hash from the NSEC5 proof in the NSEC5PROOF RR.  The client verifies
  that the NSEC5 hash is covered by the NSEC5 RR.

* The client verifies that the NSEC5 RR is validly signed by the RRSIG
  RRset.

# NSEC5 Algorithms

The algorithms used for NSEC5 authenticated denial are independent of
the algorithms used for DNSSEC signing. An NSEC5 algorithm defines how
the NSEC5 proof and the NSEC5 hash are computed and validated.

The NSEC5 proof corresponding to a name is computed using VRF_prove(), 
as specified in {{I-D.goldbe-vrf}}.
The input to VRF_prove() is 
a private NSEC5 key followed by
an RR owner name in {{RFC4034}} canonical wire format.
The output NSEC5 proof is an octet string.

An NSEC5 hash corresponding to a name is computed from 
its NSEC5 proof using VRF_proof2hash(), as specified in {{I-D.goldbe-vrf}}.
The input to VRF_proof2hash() is 
an NSEC5 proof as an octet string; 
the output NSEC5 hash is an octet string.


An NSEC5 proof for a name is verified using VRF_verify(),  as specified in
{{I-D.goldbe-vrf}}.
The input is the NSEC5 public key, 
followed by an RR owner name in {{RFC4034}} canonical wire format,
followed by an NSEC5 proof as an octet string; 
the output is either VALID or INVALID.

This document defines the EC-P256-SHA256 NSEC5 algorithm as follows:

* The VRF is the EC-VRF algorithm specified in {{I-D.goldbe-vrf}}
  (Section X) where
  the secure hash function Hash is SHA-256 and 
  the EC group G is the FIPS 186-3 P-256 curve. 
  SHA-256 is specified in {{RFC6234}}.
  The curve parameters are specified in {{FIPS-186-3}} (Section D.1.2.3)
  and {{RFC5114}} (Section 2.6). 

* The public key format to be used in the NSEC5KEY RR is defined in
  Section 4 of {{RFC6605}} and thus is the same as the format used to
  store ECDSA public keys in DNSKEY RRs.

This document defines the EC-ED25519-SHA256 NSEC5 algorithm as follows:

* The VRF is the EC-VRF algorithm specified in {{I-D.goldbe-vrf}}
  (Section X) where
  the secure hash function Hash is SHA-256 and 
  the EC group G is the Ed25519 curve. 
  SHA-256 is specified in {{RFC6234}}.
  The curve parameters are specified in
  {{RFC7748}} (Section 4.1).

* The public key format to be used in the NSEC5KEY RR is defined in
  Section 3 of {{RFC8080}} and thus is the same as the format used to
  store Ed25519 public keys in DNSKEY RRs.

# The NSEC5KEY Resource Record

The NSEC5KEY RR stores a public NSEC5 key. The key allows clients to
validate an NSEC5 proof sent by a server.

## NSEC5KEY RDATA Wire Format

The RDATA for the NSEC5KEY RR is as shown below:

~~~~
                     1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Algorithm   |                  Public Key                   /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~

Algorithm is a single octet identifying the NSEC5 algorithm.

Public Key is a variable-sized field holding public key material for
NSEC5 proof verification.

## NSEC5KEY RDATA Presentation Format

The presentation format of the NSEC5KEY RDATA is as follows:

The Algorithm field is represented as an unsigned decimal integer.

The Public Key field is represented in Base64 encoding. Whitespace is
allowed within the Base64 text.

# The NSEC5 Resource Record

The NSEC5 RR provides authenticated denial of existence for an RRset
or domain name. One NSEC5 RR represents one piece of an NSEC5 chain,
proving existence of the owner name and non-existence of other domain
names in the part of the hashed domain space that is covered until the next
owner name hashed in the RDATA.

## NSEC5 RDATA Wire Format

The RDATA for the NSEC5 RR is as shown below:

~~~~
                     1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Key Tag            |     Flags     |  Next Length  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Next Hashed Owner Name                    /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                         Type Bit Maps                         /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~

The Key Tag field contains the key tag value of the NSEC5KEY RR that
validates the NSEC5 RR, in network byte order. The value is computed
from the NSEC5KEY RDATA using the same algorithm used to
compute key tag values for DNSKEY RRs. This algorithm is defined in
{{RFC4034}}.

The Flags field is a single octet. The meaning of individual bits of
the field is defined in {{nsec5_flags}}.

The Next Length field is an unsigned single octet specifying the
length of the Next Hashed Owner Name field in octets.

The Next Hashed Owner Name field is a sequence of binary octets. It
contains an NSEC5 hash of the next domain name in the NSEC5 chain.

Type Bit Maps is a variable-sized field encoding RR types present at
the original owner name matching the NSEC5 RR. The format of the field
is equivalent to the format used in the NSEC3 RR, described in
{{RFC5155}}.

## NSEC5 Flags Field {#nsec5_flags}

The following one-bit NSEC5 flags are defined:

~~~~
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|           |W|O|
+-+-+-+-+-+-+-+-+
~~~~

> O - Opt-Out flag

> W - Wildcard flag

All the other flags are reserved for future use and MUST be zero.

The Opt-Out flag has the same semantics as in NSEC3. The definition
and considerations in {{RFC5155}} are valid, except that NSEC3 is
replaced by NSEC5.

The Wildcard flag indicates that a wildcard synthesis is possible at
the original domain name level (i.e., there is a wildcard node
immediately descending from the immediate ancestor of the original
domain name).  The purpose of the Wildcard flag is to reduce the
maximum number of RRs required for an authenticated denial of
existence proof from (at most) three to (at most) two, 
as originally described in {{I-D.gieben-nsec4}}
Section 7.2.1.

## NSEC5 RDATA Presentation Format

The presentation format of the NSEC5 RDATA is as follows:

The Key Tag field is represented as an unsigned decimal integer.

The Flags field is represented as an unsigned decimal integer.

The Next Length field is not represented.

The Next Hashed Owner Name field is represented as a sequence of
case-insensitive Base32hex digits without any whitespace and without
padding.

The Type Bit Maps representation is equivalent to the representation
used in NSEC3 RR, described in {{RFC5155}}.

# The NSEC5PROOF Resource Record

The NSEC5PROOF record is not to be included in the zone file.  The
NSEC5PROOF record contains the NSEC5 proof, proving the position of
the owner name in an NSEC5 chain.

## NSEC5PROOF RDATA Wire Format {#nsec5proof_rdata}

The RDATA for the NSEC5PROOF RR is shown below:

~~~~
                     1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Key Tag            |        Owner Name Hash        /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~

Key Tag field contains the key tag value of the NSEC5KEY RR that
validates the NSEC5PROOF RR, in network byte order.

Owner Name Hash is a variable-sized sequence of binary octets encoding
the NSEC5 proof of the owner name of the RR.

## NSEC5PROOF RDATA Presentation Format

The presentation format of the NSEC5PROOF RDATA is as follows:

The Key Tag field is represented as an unsigned decimal integer.

The Owner Name Hash is represented in Base64 encoding. Whitespace is
allowed within the Base64 text.

# Types of Authenticated Denial of Existence with NSEC5 {#nsec5_proofs}

This section summarizes all possible types of authenticated denial of
existence.  For each type the following lists are included:

1. Facts to prove: the minimum amount of information that an
  authoritative server must provide to a client to assure the client
  that the response content is valid.

2. Authoritative server proofs: the names for which the NSEC5PROOF RRs
  are synthesized and added into the response along the NSEC5 RRs
  matching or covering each such name. These records together prove
  the listed facts.

3. Validator checks: the individual checks that a validating server is
  required to perform on a response. The response content is
  considered valid only if all of the checks pass.

If NSEC5 is said to match a domain name, the owner name of the NSEC5
RR has to be equivalent to an NSEC5 hash of that domain name. If an
NSEC5 RR is said to cover a domain name, the NSEC5 hash of the domain
name must sort in canonical order between that NSEC5 RR's Owner Name
and Next Hashed Owner Name.

## Name Error Responses

Facts to prove:

> Non-existence of RRset that explictly matches the QNAME.  \[Shumon, Dave, check this terminology.]

> Non-existence of RRset that matches QNAME via wildcard expansion. \[Shumon, Dave, check this terminology.]

> The QNAME does not fall into a delegation. \[Shumon, Dave, check this terminology. "fall into"?]

> The QNAME does not fall into a DNAME redirection.

Authoritative server proofs:

> NSEC5PROOF for closest encloser and matching NSEC5 RR.

> NSEC5PROOF for next closer name and covering NSEC5 RR.

Validator checks:

> Closest encloser is in the zone.

> The NSEC5 RR matching the closest encloser has its Wildcard flag cleared.

> The NSEC5 RR matching the closest encloser does not have NS without SOA in the Type Bit Map.

> The NSEC5 RR matching the closest encloser does not have DNAME in
  the Type Bit Map.

<!--> Next closer name is derived correctly.-->

> Next closer name is not in the zone.

## No Data Responses

The processing of a No Data response for DS QTYPE differs if the
Opt-Out is in effect. For DS QTYPE queries, the validator has two
possible checking paths.  The correct path can be simply decided by
inspecting if the NSEC5 RR in the response matches the QNAME.

Note that the Opt-Out is valid only for DS QTYPE queries.

### No Data Response, Opt-Out Not In Effect

Facts to prove:

> Existence of an RRset explicitly matching the QNAME.

> Non-existence of QTYPE RRset matching the QNAME.

> Non-existence of CNAME RRset matching the QNAME.

Authoritative server proofs:

> NSEC5PROOF for the QNAME and matching NSEC5 RR.

Validator checks:

> QNAME is in the zone.

> NSEC5 RR matching the QNAME does not have QTYPE in Type Bit Map.

> NSEC5 RR matching the QNAME does not have CNAME in Type Bit Map.

### No Data Response, Opt-Out In Effect

\[Sharon has no idea how this works, someone else should check this for correctness!]

Facts to prove:

> The delegation is not covered by the NSEC5 chain.

Authoritative server proofs:

> NSEC5PROOF for closest provable encloser and matching NSEC5 RR.

Validator checks:

> Closest provable encloser is in zone.

> Closest provable encloser covers (not matches) the QNAME.  \[Sharon says that 
this terminology "covers (not matches)" is really confusing to me.  What does
"covers" mean in the context of a DNS name? Is this defined in some other
RFC? If so, maybe we should point to that other RFC?]

> NSEC5 RR matching the closest provable encloser has Opt-Out flag set.

## Wildcard Responses

Facts to prove:

> Non-existence of RRset matching the QNAME.

> Non-existence of wildcard closer to the QNAME.  \[Sharon says: what does "wildcard 
closer to the QNAME" actually mean? Probably there is a better way to say this.]

> Existence of the wildcard expansion of the QNAME. \[Sharon added this. Check 
it please!]

Authoritative server proofs:

> NSEC5PROOF for next closer name and covering NSEC5 RR.

> A signed positive response for the wildcard expansion of the QNAME, 
  as specified in <xref target="RFC4035"/>. \[Sharon says: Guys, please check this, 
  both the language and the pointer to the RFC. I added this based on 
  stuff in that chat window from 3/10/2017.]

Validator checks:

<!--> Next closer name is derived correctly.-->

> Next closer name is not in the zone.

> \[Something here about the positive response. Not sure what.]

## Wildcard No Data Responses

\[Sharon says: please check again this section, as I am not sure I understand it!]

Facts to prove:

> Non-existence of RRset that explictly matches the QNAME.  \[Shumon, Dave, check this terminology.]

> Non-existence of QTYPE RRset that matches QNAME via wildcard expansion. \[Shumon, Dave, check this terminology.]

> Non-existence of CNAME RRset that matches QNAME via wildcard expansion. 

> No wildcard closer to the QNAME exists.  \[Sharon says as before I don't understand
what this means.]

Authoritative server proofs:

> NSEC5PROOF for source of synthesis (i.e., wildcard at closest
encloser) and matching NSEC5 RR.

> NSEC5PROOF for next closer name and covering NSEC5 RR.

Validator checks:

> Source of synthesis matches the QNAME. \[Sharon says: again, I'm not sure what 
this means. Are we saying "Source of synthesis matches QNAME via wildcard expansion." ?]

> NSEC5 RR matching source of synthesis does not have QTYPE in Type Bit Map.

> NSEC5 RR matching source of synthesis does not have CNAME in Type Bit Map.

<!--> Next closer name is derived correctly.-->

> Next closer name is not in the zone.


# Authoritative Server Considerations

## Zone Signing {#zone_signing}

Zones using NSEC5 MUST satisfy the same properties as described in
Section 7.1 of {{RFC5155}}, with NSEC3 replaced by NSEC5. In addition,
the following conditions MUST be satisfied as well:

* If the original owner name has a wildcard label immediately
  descending from the original owner name, the corresponding NSEC5 RR
  MUST have the Wildcard flag set in the Flags field. Otherwise, the
  flag MUST be cleared.

* The zone apex MUST include an NSEC5KEY RRset containing a NSEC5
  public key allowing verification of the current NSEC5 chain.

The following steps describe one possible method to properly add
required NSEC5 related records into a zone. This is not the only such
existing method.

1. Select an algorithm for NSEC5.  Generate the public and private NSEC5 keys.

2. Add an NSEC5KEY RR into the zone apex containing the public NSEC5 key.

3. For each unique original domain name in the zone and each empty
  non-terminal, add an NSEC5 RR. If Opt-Out is used, owner names of
  unsigned delegations MAY be excluded.

    A. The owner name of the NSEC5 RR is the NSEC5 hash of the
      original owner name encoded in Base32hex without padding,
      prepended as a single label to the zone name.

    B. Set the Key Tag field to be the key tag corresponding
      to the public NSEC5 key.

    C. Clear the Flags field. If Opt-Out is being used, set the Opt-Out
      flag. If there is a wildcard label directly descending from the
      original domain name, set the Wildcard flag. Note that the
      wildcard can be an empty non-terminal (i.e., the wildcard synthesis
      does not take effect and therefore the flag is not to be set).

    D. Set the Next Length field to a value determined by the used
      NSEC5 algorithm. Leave the Next Hashed Owner Name field blank.

    E. Set the Type Bit Maps field based on the RRsets present at the
      original owner name.

4. Sort the set of NSEC5 RRs into canonical order.

5. For each NSEC5 RR, set the Next Hashed Owner Name field by using
  the owner name of the next NSEC5 RR in the canonical order. If the
  updated NSEC5 is the last NSEC5 RR in the chain, the owner name of the
  first NSEC5 RR in the chain is used instead.

The NSEC5KEY and NSEC5 RRs MUST have the same class as the zone SOA
RR.  Also the NSEC5 RRs SHOULD have the same TTL value as the SOA
minimum TTL field.

Notice that a use of Opt-Out is not indicated in the zone. This does
not affect the ability of a server to prove insecure delegations. The
Opt-Out MAY be part of the zone-signing tool configuration.

### Precomputing Closest Provable Encloser Proofs {#precompute}

Per {{nsec5_proofs}}, the worst-case scenario when answering a negative 
query with NSEC5 requires authoritative server to respond with two 
NSEC5PROOF RRs and
two NSEC5 RRs. One pair of NSEC5PROOF and NSEC5
RRs corresponds to the closest provable encloser, and the other pair
corresponds to the next closer name.  The NSEC5PROOF corresponding to
the next closer name MUST be computed on the fly by the authoritative
server when responding to the query. However, the NSEC5PROOF
corresponding to the closest provable encloser MAY be precomputed and
stored as part of zone signing.

Precomputing NSEC5PROOF RRs can halve the number of online
cryptographic computations required when responding to a negative
query. NSEC5PROOF RRs MAY be precomputed as part of zone signing as
follows: For each NSEC5 RR, compute an NSEC5PROOF RR corresponding to
the original owner name of the NSEC5 RR. The content of the
precomputed NSEC5PROOF record MUST be the same as if the record was
computed on the fly when serving the zone.  NSEC5PROOF records are not
part of the zone and SHOULD be stored separately from the zone file.

## Zone Serving

This specification modifies DNSSEC-enabled DNS responses generated by
authoritative servers. In particular, it replaces use of NSEC or NSEC3
RRs in such responses with NSEC5 RRs and adds NSEC5PROOF RRs.

According to the type of a response, an authoritative server MUST
include NSEC5 RRs in the response, as defined in {{nsec5_proofs}}. For
each NSEC5 RR in the response, a corresponding RRSIG RRset and an
NSEC5PROOF MUST be added as well. The NSEC5PROOF RR has its owner name
set to the domain name required according to the description in 
{{nsec5_proofs}}. The
class and TTL of the NSEC5PROOF RR MUST be the same as the class and
TTL value of the corresponding NSEC5 RR. The RDATA payload of the
NSEC5PROOF is set according to the description in
{{nsec5proof_rdata}}.

Notice that the NSEC5PROOF owner name can be a wildcard (e.g., source
of synthesis proof in wildcard No Data responses). The name also
always matches the domain name required for the proof while the NSEC5
RR may only cover (not match) the name in the proof (e.g., closest
encloser in Name Error responses).

If NSEC5 is used, an answering server MUST use exactly one NSEC5 chain
for one signed zone.

NSEC5 MUST NOT be used in parallel with NSEC, NSEC3, or any other
authenticated denial of existence mechanism that allows for
enumeration of zone contents, as this would defeat a principal
security goal of NSEC5.

Similarly to NSEC3, the owner names of NSEC5 RRs are not represented
in the NSEC5 chain and therefore NSEC5 records deny their own
existence. The desired behavior caused by this paradox is the same as
described in Section 7.2.8 of {{RFC5155}}.

## NSEC5KEY Rollover Mechanism

Replacement of the NSEC5 key implies generating a new NSEC5 chain. The
NSEC5KEY rollover mechanism is similar to "Pre-Publish Zone Signing
Key Rollover" as specified in {{RFC6781}}. The NSEC5KEY rollover MUST
be performed as a sequence of the following steps:

1. A new public NSEC5 key is added into the NSEC5KEY RRset in the zone
  apex.

2. The old NSEC5 chain is replaced by a new NSEC5 chain constructed
  using the new key. This replacement MUST happen as a single atomic
  operation; the server MUST NOT be responding with RRs from both the
  new and old chain at the same time.

3. The old public key is removed from the NSEC5KEY RRset in the zone
  apex.

The minimum delay between steps 1 and 2 MUST be the time it takes for
the data to propagate to the authoritative servers, plus the TTL value
of the old NSEC5KEY RRset.

The minimum delay between steps 2 and 3 MUST be the time it takes for
the data to propagate to the authoritative servers, plus the maximum
zone TTL value of any of the data in the previous version of the zone.

## Secondary Servers

This document does not define mechanism to distribute private NSEC5 keys.
See {{keyleak}} for security considerations for private NSEC5 keys.

## Zones Using Unknown NSEC5 Algorithms

Zones that are signed with an unknown NSEC5 algorithm or with an
unavailable private NSEC5 key cannot be effectively served. Such zones
SHOULD be rejected when loading and servers SHOULD respond with
RCODE=2 (Server failure) when handling queries that would fall under
such zones.

## Dynamic Updates

A zone signed using NSEC5 MAY accept dynamic updates {{RFC2136}}.  The
changes to the zone MUST be performed in a way that ensures that the
zone satisfies the properties specified in {{zone_signing}} at any
time.  The process described in {{RFC5155}} Section 7.5 describes how
to handle the issues surrounding the handling of empty non-terminals
as well as Opt-Out.

It is RECOMMENDED that the server rejects all updates containing
changes to the NSEC5 chain and its related RRSIG RRs, and performs
itself any required alternations of the NSEC5 chain induced by the
update.  Alternatively, the server MUST verify that all the properties
are satisfied prior to performing the update atomically.

# Resolver Considerations

The same considerations as described in Section 9 of {{RFC5155}} for
NSEC3 apply to NSEC5. In addition, as NSEC5 RRs can be validated only
with appropriate NSEC5PROOF RRs, the NSEC5PROOF RRs MUST be all
together cached and included in responses with NSEC5 RRs.

# Validator Considerations

## Validating Responses

The validator MUST ignore NSEC5 RRs with Flags field values other than
the ones defined in {{nsec5_flags}}.

The validator MAY treat responses as bogus if the response contains
NSEC5 RRs that refer to a different NSEC5KEY.

According to a type of a response, the validator MUST verify all
conditions defined in {{nsec5_proofs}}. Prior to making decision based
on the content of NSEC5 RRs in a response, the NSEC5 RRs MUST be
validated.

To validate a denial of existence, public NSEC5 keys for the zone are
required in addition to DNSSEC public keys. Similarly to DNSKEY RRs,
the NSEC5KEY RRs are present at the zone apex.

The NSEC5 RR is validated as follows:

1. Select a correct public NSEC5 key to validate the NSEC5 proof. The
  Key Tag value of the NSEC5PROOF RR must match with the key tag value
  computed from the NSEC5KEY RDATA.

2. Validate the NSEC5 proof present in the NSEC5PROOF Owner Name Hash
  field using the public NSEC5 key. If there are multiple NSEC5KEY RRs
  matching the key tag, at least one of the keys must validate the
  NSEC5 proof.

3. Compute the NSEC5 hash value from the NSEC5 proof and check if the
  response contains NSEC5 RR matching or covering the computed NSEC5
  hash.  The TTL values of the NSEC5 and NSEC5PROOF RRs must be the
  same.

4. Validate the signature on the NSEC5 RR.

If the NSEC5 RR fails to validate, it MUST be ignored. If some of the
conditions required for an NSEC5 proof are not satisfied, the response
MUST be treated as bogus.

Notice that determining the closest encloser and next closer name in
NSEC5 is easier than in NSEC3. NSEC5 and NSEC5PROOF RRs are always
present in pairs in responses and the original owner name of the NSEC5
RR matches the owner name of the NSEC5PROOF RR.

## Validating Referrals to Unsigned Subzones

The same considerations as defined in Section 8.9 of {{RFC5155}} for
NSEC3 apply to NSEC5.

## Responses With Unknown NSEC5 Algorithms

A validator MUST ignore NSEC5KEY RRs with unknown NSEC5
algorithms. The practical result of this is that zones signed with
unknown algorithms will be considered bogus.

# Special Considerations

## Transition Mechanism

\[TODO: The following information will be covered.]

* Transition to NSEC5 from NSEC/NSEC3

* Transition from NSEC5 to NSEC/NSEC3

* Transition to new NSEC5 algorithms

## Private NSEC5 keys

This document does not define a format to store private NSEC5
keys. Use of a standardized and adopted format is RECOMMENDED.

The private NSEC5 key MAY be shared between multiple zones, however a
separate key is RECOMMENDED for each zone.

## Domain Name Length Restrictions

NSEC5 creates additional restrictions on domain name lengths. In
particular, zones with names that, when converted into hashed owner
names, exceed the 255 octet length limit imposed by {{RFC1035}} cannot
use this specification.

The actual maximum length of a domain name depends on the length of
the zone name and the NSEC5 algorithm used.

All NSEC5 algorithms defined in this document use 256-bit NSEC5 hash
values.  Such a value can be encoded in 52 characters in Base32hex
without padding.  When constructing the NSEC5 RR owner name, the
encoded hash is prepended to the name of the zone as a single label
which includes the length field of a single octet.  The maximum length
of the zone name in wire format using the 256-bit hash is therefore
202 octets (255 - 53).

# Implementation Status {#implementation-status}

NSEC5 has been implemented for the Knot DNS authoritative server
(version 1.6.4) and the Unbound recursive server (version 1.5.9).  The
implementations did not introduce additional library dependencies; all
cryptographic primitives are already present in OpenSSL v1.0.2j, which
is used by both implementations.  The implementations support the full
spectrum of negative responses, (i.e., NXDOMAIN, NODATA, Wildcard,
Wildcard NODATA, and unsigned delegation) using the EC-P256-SHA256
algorithm. The code is deliberately modular, so that the
EC-ED25519-SHA256 algorithm could be implemented by using the Ed25519
elliptic curve {{RFC8080}} as a drop-in replacement for the P256
elliptic curve.  The authoritative server implements the optimization
from {{precompute}} to precompute the NSEC5PROOF RRs matching each
NSEC5 record.

# Performance Considerations

The performance of NSEC5 has been evaluated in {{nsec5ecc}}.

# Security Considerations

## Zone Enumeration Attacks {#zea}

NSEC5 is robust to zone enumeration via offline dictionary attacks by
any attacker that does not know the private NSEC5 key. Without the
private NSEC5 key, that attacker cannot compute the NSEC5 proof that
corresponds to a given domain name.  The only way it can learn the
NSEC5 proof value for a domain name is by querying the authoritative
server for that name. Without the NSEC5 proof value, the attacker
cannot learn the NSEC5 hash value. Thus, even an attacker that
collects the entire chain of NSEC5 RR for a zone cannot use offline
attacks to "reverse" that NSEC5 hash values in these NSEC5 RR and thus
learn which names are present in the zone.  A formal cryptographic
proof of this property is in {{nsec5}} and {{nsec5ecc}}.

## Compromise of the Private NSEC5 Key {#keyleak}

NSEC5 requires authoritative servers to hold the private NSEC5 key,
but not the private zone-signing keys or the private key-signing keys
for the zone.

The private NSEC5 key cannot be used to modify zone contents, because
zone contents are signed using the private zone-signing key.  As such,
a compromise of the private NSEC5 key does not compromise the
integrity of the zone.  An adversary that learns the private NSEC5 key
can, however, perform offline zone-enumeration attacks.  For this
reason, the private NSEC5 key need only be as secure as the DNSSEC
records whose privacy (against zone enumeration) is being protected by
NSEC5.  A formal cryptographic proof of this property is in {{nsec5}}
and {{nsec5ecc}}.

To preserve this property of NSEC5, the private NSEC5 key MUST be
different from the private zone-signing keys or key-signing keys for
the zone.

## Key Length Considerations {#keylen}

The NSEC5 key must be long enough to withstand attacks for as long as
the privacy of the zone contents is important. Even if the NSEC5 key
is rolled frequently, its length cannot be too short, because zone
privacy may be important for a period of time longer than the lifetime
of the key.  For example, an attacker might collect the entire chain
of NSEC5 RR for the zone over one short period, and then, later (even
after the NSEC5 key expires) perform an offline dictionary attack that
attempts to reverse the NSEC5 hash values present in the NSEC5 RRs.
This is in contrast to zone-signing and key-signing keys used in
DNSSEC; these keys, which ensure the authenticity and integrity of the
zone contents, need to remain secure only during their lifetime.


## NSEC5 Hash Collisions {#hashcol}

If the NSEC5 hash of a QNAME collides with the NSEC5 hash of the owner
name of an NSEC5 RR, it will be impossible to prove the non-existence
of the colliding QNAME. However, the NSEC5 VRFs ensure that obtaining
such a collision is as difficult as obtaining a collision in the
SHA-256 hash function, requiring approximately 2^128 effort. Note that
DNSSEC already relies on the assumption that a cryptographic hash
function is collision-resistant, since these hash functions are used
for generating and validating signatures and DS RRs. See also the
discussion on key lengths in {{nsec5}}.

# IANA Considerations {#iana_considerations}

This document updates the IANA registry "Domain Name System (DNS)
Parameters" in subregistry "Resource Record (RR) TYPEs", by defining
the following new RR types:

> NSEC5KEY   value TBD.

> NSEC5      value TBD.

> NSEC5PROOF value TBD.

This document creates a new IANA registry for NSEC5 algorithms.  This
registry is named "DNSSEC NSEC5 Algorithms". The initial content of
the registry is:

> 0     is Reserved.

> 1     is EC-P256-SHA256.

> 2     is EC-ED25519-SHA256.

> 3-255 is Available for assignment.

This document updates the IANA registry "DNS Security Algorithm
Numbers" by defining following aliases:

> TBD is NSEC5-ECDSAP256SHA256 alias for ECDSAP256SHA256 (13).

> TBD is NSEC5-ED25519, alias for ED25519 (15).


# Contributors

This document would not be possible without help of
Moni Naor (Weizmann Institute),
Sachin Vasant (Cisco Systems),
Leonid Reyzin (Boston University), and
Asaf Ziv (Weizmann Institute)
who contributed to the design of NSEC5.
Ondrej Sury (CZ.NIC Labs), and
Duane Wessels (Verisign Labs)
provided advice on the implementation of NSEC5, and assisted with
evaluating its performance.

--- back


# Examples

We use small DNS zone 
to illustrate how denying responses are handled with NSEC5.  For brevity,
the class is not shown (defaults to IN) and the SOA record is shortened,
resulting in the following zone file:

    example.org.        SOA ( ... )  
    example.org.        NS  a.example.org

    a.example.org.      A 192.0.2.1  
    
    c.example.org.      A 192.0.2.2  
    c.example.org.      TXT "c record"  

    d.example.org.      NS ns1.d.example.org

    ns1.d.example.org.  A 192.0.2.4

    g.example.org.      A 192.0.2.1  
    g.example.org.      TXT "g record"

    *.a.example.org.    TXT "wildcard record"

Next we present example responses. All cryptographic values are
shortened as indicated by "..." and ADDITIONAL sections have been
removed.

## Name Error Example

Consider a query for a type A record for a.b.c.example.org.

The server must prove the following facts:

* Existence of closest encloser c.example.org.

* Non-existence of wildcard at closest encloser *.c.example.org.

* Non-existence of next closer b.c.example.org.

<!-- tale should figure out the right way to keep this on one page -->
To do this, the server returns:

    ;; ->>HEADER<<- opcode: QUERY; status: NXDOMAIN; id: 5937 
 
    ;; QUESTION SECTION:  
    ;; a.b.c.example.org.           IN      A

    ;; AUTHORITY SECTION:  
    example.org.         3600 IN SOA a.example.org. hostmaster.example.org. (  
                2010111214 21600 3600 604800 86400 )

    example.org.         3600 IN RRSIG  SOA 16 2 3600 (  
                20170412024301 20170313024301 5137 example.org. rT231b1rH... )

This is an NSEC5PROOF RR for c.example.com. It's RDATA is the NSEC5 proof 
corresponding to c.example.com.  (NSEC5 proofs are randomized values,
because NSEC5 proof values are computed uses the EC-VRF 
from <xref target="I-D.goldbe-vrf"/>.)
Per {{precompute}}, this NSEC5PROOF RR may be precomputed.

    c.example.org.      86400 IN NSEC5PROOF 48566 Amgn22zUiZ9JVyaT...

This is a signed NSEC5 RR "matching" c.example.org, which proves 
the existence of closest encloser c.example.org.
The NSEC5 RR has its owner name equal to the
NSEC5 hash of c.example.org, which is O4K89V.  (NSEC5 hash values are 
deterministic given the public NSEC5 key.)
The NSEC5 RR also has its Wildcard flag cleared (see the "0" after the key ID 
48566). This proves the non-existence of the wildcard 
at the closest encloser *.c.example.com.
NSEC5 RRs are  precomputed.

    o4k89v.example.org. 86400 IN NSEC5   48566 0 0O49PI A TXT RRSIG  
    o4k89v.example.org. 86400 IN RRSIG   NSEC5 16 3 86400 (  
                20170412024301 20170313024301 5137 example.org. zDNTSMQNlz... )

This is an NSEC5PROOF RR for b.c.example.org. It's RDATA is the NSEC5 proof 
corresponding to b.c.example.com.  This NSEC5PROOF RR must be computed on-the-fly.

    b.c.example.org.    86400 IN NSEC5PROOF 48566 AuvvJqbUcEs8sCpY...

This is a signed  NSEC5 RR "covering" b.c.example.org, which proves the
non-existence of the next closer name b.c.example.org
The NSEC5 hash of b.c.example.org, which is AO5OF, sorts in canonical 
order between the "covering" NSEC5 RR's Owner Name (which is 0O49PI)
and Next Hashed Owner Name (which is BAPROH).

    0o49pi.example.org. 86400 IN NSEC5      48566 0 BAPROH (
                NS SOA RRSIG DNSKEY NSEC5KEY )

    0o49pi.example.org. 86400 IN RRSIG   NSEC5 16 3 86400 (
                20170412024301 20170313024301 5137 example.org. 4HT1uj1YlMzO)

    [TODO: Add discussion of CNAME and DNAME to the example?]

## No Data Example, Opt-Out Not In Effect

Consider a query for a type MX record for c.example.org.

The server must prove the following facts:

* Existence of c.example.org. for any type other than MX or CNAME

To do this, the server returns:

    ;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 38781

    ;; QUESTION SECTION:
    ;; c.example.org.    IN MX

    ;; AUTHORITY SECTION:
    example.org.    3600 IN SOA     a.example.org. hostmaster.example.org. (
                2010111214 21600 3600 604800 86400 )

    example.org.    3600 IN RRSIG   SOA 16 2 3600 20170412024301 20170313024301 5137 example.org. /rT231b1rH/p

This is an NSEC5PROOF RR for c.example.com. Its RDATA corresponds to the NSEC5
proof for c.example.com. which is a randomized value.  Per {{precompute}}, this
NSEC5PROOF RR may be precomputed.

    c.example.org. 86400 IN NSEC5PROOF 48566 Amgn22zUiZ9JVyaT

This is a signed NSEC5 RR "matching" c.example.org. with CNAME and 
MX Type Bits cleared and its TXT Type Bit set. This NSEC5 RR has its owner
name equal to the NSEC5 hash of c.example.org. This proves the existence of
c.example.org. for a type other than MX and CNAME. 
NSEC5 RR are precomputed.

    o4k89v.example.org. 86400 IN NSEC5   48566 0 0O49PI A TXT RRSIG

    o4k89v.example.org. 86400 IN RRSIG   NSEC5 16 3 86400 (
                20170412024301 20170313024301 5137 example.org. zDNTSMQNlz/J)

## No Data Example, Opt-Out In Effect

\[Dimitris: This case separation reads kind of awkward. 
I would rather rename this section to Delegation to Unisgned Opt-out zone and the previous to simply No Data]

Consider a query for a type A record for foo.d.example.org.

The server must prove the following facts:

* Existence of closest provable encloser example.org

* Non-existence of next closer d.example.org  [THIS NEEDS TO BE REWORDED!
    d.ex.com exists by is unsigned!!!]

* Opt-out bit is set in the closest provable encloser NSEC5 record

To do this, the server returns:

    ;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 45866

    ;; QUESTION SECTION:
    ;; foo.d.example.org.         IN A

    ;; AUTHORITY SECTION:
    d.example.org.       3600  IN NS      ns1.d.example.org.

This is an NSEC5PROOF RR for example.com. It's RDATA is the NSEC5 proof 
corresponding to example.com.  Per {{precompute}}, this NSEC5PROOF RR may be precomputed.

    example.org.        86400 IN NSEC5PROOF      48566 AjwsPCJZ8zH/D0Tr

This is a signed NSEC5 RR "matching" example.org. This NSEC5 RR has its owner
name equal to the NSEC5 hash of example.org which is 0O49PI.  
NSEC5 RR are   precomputed.

    0o49pi.example.org. 86400 IN NSEC5   48566 0 BAPROH (
                NS SOA RRSIG DNSKEY NSEC5KEY)

    0o49pi.example.org. 86400 IN RRSIG   NSEC5 16 3 86400 (
                20170412034216 20170313034216 5137 example.org. 4HT1uj1YlMzO)

This is an NSEC5PROOF RR for d.example.org.  It's RDATA is the NSEC5 proof 
corresponding to d.example.org. This NSEC5PROOF RR is computed on the fly.

    d.example.org.      86400   IN      NSEC5PROOF      48566 A9FpmeH79q7g6VNW

This is a signed NSEC5 RR "covering" d.example.org with its Opt-out bit set 
(see the "1" after the key ID 48566).
The NSEC5 hash of d.example.org (which is BLE8LR) sorts in canonical order between the
"covering" NSEC5 RR's Owner Name (BAPROH) and Next Hashed Owner Name (JQBMG4).

    baproh.example.org. 86400 IN NSEC5   48566 1 JQBMG4 A TXT RRSIG

    baproh.example.org. 86400 IN RRSIG   NSEC5 16 3 86400 (
                20170412024301 20170313024301 5137 example.org. fjTcoRKgdML1)

## Wildcard Example

Consider a query for a type TXT record for foo.a.example.org.

The server must prove the following facts:

* Existence of the TXT record for the wildcard *.a.example.org

* Non-existence of the next closer name foo.a.example.org.

To do this, the server returns:

    ;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 53731

    ;; QUESTION SECTION:
    ;; foo.a.example.org.        IN TXT

This is a signed TXT record for the wildcard at a.example.org 
(number of labels is set to 3 in the RRSIG record).

    ;; ANSWER SECTION:
    foo.a.example.org.      3600 IN TXT     "wildcard record"

    foo.a.example.org.      3600 IN RRSIG   TXT 16 3 3600 (
                20170412024301 20170313024301 5137 example.org. aeaLgZ8sk+98)

    ;; AUTHORITY SECTION:
    example.org.            3600 IN NS      a.example.org.

    example.org.            3600 IN RRSIG   NS 16 2 3600 (
                20170412024301 20170313024301 5137 example.org. 8zuN0h2x5WyF)

This is an NSEC5PROOF RR for foo.a.example.org.  This
 NSEC5PROOF RR must be computed on-the-fly.

    foo.a.example.org.     86400 IN NSEC5PROOF      48566 AjqF5FGGVso40Lda

This is a signed NSEC5 RR "covering" foo.a.example.org. The NSEC5 hash of
foo.a.example.org is FORDMO and sorts in canonical order between the 
NSEC5 RR's Owner Name (which is BAPROH) and Next Hashed Owner Name 
(which is JQBMG4). This proves the non-existence of the next closer
name foo.a.example.com.
NSEC5 RRs are   precomputed.

        baproh.example.org. 86400 IN NSEC5   48566 1 JQBMG4 A TXT RRSIG
        baproh.example.org. 86400 IN RRSIG   NSEC5 16 3 86400 (
            20170412024301 20170313024301 5137 example.org. fjTcoRKgdML1

## Wildcard No Data Example

Consider a query for a type MX record for foo.a.example.org.

The server must prove the following facts:

* Existence of wildcard at closest encloser
  *.a.example.org. for any type other than MX or CNAME.

* Non-existence of the next closer name foo.a.example.org.

To do this, the server returns:

    ;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 17332

    ;; QUESTION SECTION:
    ;; foo.a.example.org.           IN      MX

    ;; AUTHORITY SECTION:
    example.org.       3600 IN SOA     a.example.org. hostmaster.example.org. (
                2010111214 21600 3600 604800 86400 )

    example.org.       3600 IN RRSIG   SOA 16 2 3600 (
                20170412024301 20170313024301 5137 example.org. /rT231b1rH/p )

This is an NSEC5PROOF RR for *.a.example.com, with RDATA equal to the NSEC5 
proof for *.a.example.com. Per {{precompute}}, this NSEC5PROOF RR may be precomputed.

    *.a.example.org.  86400 IN NSEC5PROOF      48566 Aq38RWWPhbs/vtih

This is a signed NSEC5 RR "matching" *.a.example.org with 
its CNAME and MX Type Bits cleared and its TXT Type Bit set.
This NSEC5 RR has its owner name equal to the NSEC5 hash of *.a.example.org. 
NSEC5 RRs are   precomputed.

    mpu6c4.example.org. 86400 IN NSEC5   48566 0 O4K89V TXT RRSIG

    mpu6c4.example.org. 86400 IN RRSIG   NSEC5 16 3 86400 (
                20170412024301 20170313024301 5137 example.org. m3I75ttcWwVC )

This is an NSEC5PROOF RR for foo.a.example.com. This NSEC5PROOF RR must be 
computed on-the-fly.

    foo.a.example.org.  86400 IN NSEC5PROOF      48566 AjqF5FGGVso40Lda

This is a signed NSEC5 RR "covering" foo.a.example.org. The NSEC5 hash of
foo.a.example.org is FORDMO, and sorts in canonical order between this
covering NSEC5 RR's Owner Name (which is BAPROH) and Next Hashed Owner Name
(which is JQBMG4).   This proves the existence of the wildcard at closest encloser
*.a.example.org. for any type other than MX or CNAME. 
NSEC5 RRs are   precomputed.

    baproh.example.org. 86400 IN NSEC5   48566 1 JQBMG4 A TXT RRSIG

    baproh.example.org. 86400 IN RRSIG   NSEC5 16 3 86400 (
                20170412024301 20170313024301 5137 example.org. fjTcoRKgdML1 )

# Change Log

Note to RFC Editor: if this document does not obsolete an existing
RFC, please remove this appendix before publication as an RFC.

> pre 00 - initial version of the document submitted to mailing list only

> 00 - fix NSEC5KEY rollover mechanism, clarify NSEC5PROOF RDATA,
> clarify inputs and outputs for NSEC5 proof and NSEC5 hash
> computation.

> 01 - Add Performance Considerations section.

> 02 - Add elliptic curve based VRF. Add measurement of response sizes
> based on empirical data.

> 03 - Mention precomputed NSEC5PROOF Values in Performance
> Considerations section.

> 04 - Edit Rationale, How NSEC5 Works, and Security Consideration
> sections for clarity.  Edit Zone Signing section, adding
> precomputation of NSEC5PROOFs.  Remove RSA-based NSEC5
> specification.  Rewrite Performance Considerations and
> Implementation Status sections.
