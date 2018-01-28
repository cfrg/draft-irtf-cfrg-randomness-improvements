---
title: Randomness Improvements for Security Protocols
abbrev: Randomness Improvements 
docname: draft-sullivan-cfrg-randomness-improvements-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
    -
        ins: C. Cramers
        name: Cas Cremers
        org: University of Oxford
        street: Wolfson Building, Parks Road
        city: Oxford
        country: England
        email: cas.cremers@cs.ox.ac.uk
    -
        ins: L. Garratt
        name: Luke Garratt
        org: University of Oxford
        street: Wolfson Building, Parks Road
        city: Oxford
        country: England
        email: luke.garratt@wolfson.ox.ac.uk
    -
        ins: S. Smyshlyaev
        name: Stanislav Smyshlyaev
        org: CryptoPro
        street: 18, Suschevsky val
        city: Moscow
        country: Russian Federation
        email: svs@cryptopro.ru
    -
        ins: N. Sullivan
        name: Nick Sullivan
        org: Cloudflare
        street: 101 Townsend St
        city: San Francisco
        country: United States of America
        email: nick@cloudflare.com
    -
        ins: C. Wood
        name: Christopher A. Wood
        org: Apple
        street: 1 Infinite Loop
        city: Cupertino
        country: United States of America
        email: cawood@apple.com

normative:
    RFC2104:
    RFC5869:
    RFC6979:
    X9.62:
        title: Public Key Cryptography for the Financial Services Industry -- The Elliptic Curve Digital Signature Algorithm (ECDSA). ANSI X9.62-2005, November 2005.
        author:
            -
                ins: American National Standards Institute
    DebianBug:
        title: When private keys are public - Results from the 2008 Debian OpenSSL vulnerability
        author:
            -
                ins: Yilek, Scott, et al.
        target: https://pdfs.semanticscholar.org/fcf9/fe0946c20e936b507c023bbf89160cc995b9.pdf
    DualEC:
        title: Dual EC - A standardized back door
        author:
            -
                ins: Bernstein, Daniel et al.
        target: https://projectbullrun.org/dual-ec/documents/dual-ec-20150731.pdf
    NAXOS:
        title: Stronger Security of Authenticated Key Exchange
        author:
            -
                ins: LaMacchia, Brian et al.
        target: https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/strongake-submitted.pdf

--- abstract

Randomness is a crucial ingredient for TLS and related security protocols.
Weak or predictable "cryptographically-strong" pseudorandom number generators (CSPRNGs)
can be abused or exploited for malicious purposes. (See the Dual EC random number
backdoor for a relevant example of this problem.) This document describes a way for
security protocol participants to mix their long-term private key into the entropy pool from 
which random values are derived. This may help mitigate problems that stem from broken CSPRNGs.

--- middle

# Introduction

Randomness is a crucial ingredient for TLS and related transport security protocols.
TLS in particular uses Random Number Generators (RNGs) to generate several values: session IDs,
ephemeral key shares, and ClientHello and ServerHello random values. RNG failures
such as the Debian bug described in {{DebianBug}} can lead to insecure TLS connections.
RNGs may also be intentionally weakened to cause harm {{DualEC}}.
In such cases where RNGs are poorly implemented or insecure, an adversary may be
able to predict its output and recover secret Diffie-Hellman key shares that protect
the connection.

This document proposes an improvement to randomness generation in security protocols
inspired by the "NAXOS trick" {{NAXOS}}. Specifically, instead of using raw entropy
where needed, e.g., in generating ephemeral key shares, a party's long-term private key
is mixed into the entropy pool. In the NAXOS key exchange protocol, raw entropy
output x is replaced by H(x, sk), where sk is the sender's private key.
Unfortunately, as private keys are often isolated in HSMs,
direct access to compute H(x, sk) is impossible. An alternate yet functionally
equivalent construction is needed.

The approach described herein replaces the NAXOS hash with a keyed hash, or pseudorandom function (PRF), 
where the key is derived from raw entropy output and a private key signature.
Implementations SHOULD apply this technique when indirect access to a private key
is available and CSPRNG randomness guarantees are dubious.

# Randomness Wrapper

Let x be the raw entropy output of a CSPRNG. When properly instantiated, x should be
indistinguishable from a random string of length |x|. However, as previously discussed,
this is not always true. To mitigate this problem, we propose an approach for wrapping
the CSPRNG output with a construction that artificially injects randomness into
a value that may be lacking entropy.

Let PRF(k, m) be a cryptographic pseudorandom function, e.g., HMAC {{RFC2104}}, that
takes as input a key k of length L and message m and produces an output of length M. 
For example, when using HMAC with SHA256, L and M are 256 bits.
Let Sig(sk, m) be a function that computes a signature of message m given
private key sk. Let G be an algorithm that generates random numbers from raw entropy, i.e., the
output of a CSPRNG. Let tag be a fixed, context-dependent string. Let KDF be a key derivation
function, e.g., HKDF-Extract {{RFC5869}}, that extracts a key of length L
suitable for cryptographic use. Lastly, let H be a cryptographic hash function
that produces output of length M.

The construction is simple: instead of using x when randomness is needed,
use:

~~~
PRF(KDF(G(x) || H(Sig(sk, tag))), tag)
~~~

Functionally, this computes the PRF of a fixed string (tag) with a key derived from
the CSPRNG output and signature over the fixed string (tag). See section {{sec:tag-gen}} for
details about how "tag" should be generated. The PRF behaves like
a truly random function from 2^L to 2^M assuming the key is selected at random.
Thus, the security of this construction depends on secrecy of H(Sig(sk, tag)) and
G(x). If both are leaked, then the security reduces to the scenario wherein this
wrapping construction is not applied. If G(x) is predictable, then security reduces 
to randomness of H(Sig(sk, tag)).

In systems where signature computations are not cheap, these values may be precomputed
in anticipation of future randomness requests. This is possible since the construction
depends solely upon the CSPRNG output and private key. 

Sig should be a deterministic signature function, e.g., deterministic ECDSA {{RFC6979}}.
In cases where randomized signature algorithms are used, such as RSA-PSS or non-deterministic 
ECDSA {{X9.62}}, the output should be used to (re-)seed the CSPRNG, after which the construction
should no longer be used. This helps minimize key reuse when not needed.

# Tag Generation {#sec:tag-gen}

Tags SHOULD be generated such that they never collide with another accessor or owner
of the private key. This can happen if, for example, one HSM with a private key is
used from several servers, or if virtual machines are cloned.

To mitigate collisions, tag strings SHOULD:

1. Include a unique timestamps or counter.
2. Include some data that is specific for a particular device, e.g., MAC
address. 
3. Be specific to the protocol in use. (See Section {{sec:tls13}} for an example
string to be used in the context of TLS 1.3.)

# Application to TLS {#sec:tls13}

The PRF randomness wrapper can be applied to any protocol wherein a party has
a long-term private key and also generates randomness. This is true of most
TLS servers. Thus, to apply this construction to TLS, one simply replaces the
"private" PRNG, i.e., the PRNG that generates private values, such as key shares,
with:

~~~
HMAC(HKDF-Extract(nil, G(x) || Sig(sk, tag)), tag)
~~~

Moreover, we fix tag as "TLS 1.3 Additional Entropy" for TLS 1.3. Older variants
use similarly constructed strings.

# IANA Considerations

This document makes no request to IANA.

# Security Considerations

A security analysis was performed by two authors of this document. Generally speaking,
security depends on keeping the private key secret. If this secret is compromised, the
scheme reduces to the scenario wherein the PRF random wrapper was not applied in the first place.

