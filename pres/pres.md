---
marp: true
lang: en-US
title: Trapped by the CLI
description: How your favorite cryptographic toolkit can fool you - Nullcon Goa 2025
theme: default
class: invert
transition: none
paginate: true
_paginate: false
header: 'Nullcon Goa 2025 - Trapped by the CLI'
_header: ''
footer: 'William Robinet - Conostix S.A. - https://github.com/wllm-rbnt/trapped-by-the-CLI'
style: |
  .columns {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 1rem;
  }

  section.smallcode pre {
    font-size: 18px;
    background: black;
    color: #F0F6FC;
    border-color: black;
  }

  section.smallcode {
    background: black;
    color: #F0F6FC;
  }

  img[alt~="top-right"] {
    position: absolute;
    top: 30px;
    right: 30px;
  }
 
  img[alt~="top-left"] {
    position: absolute;
    top: 160px;
    left: 140px;
  }
 
  img[alt~="bottom-right"] {
    position: absolute;
    top: 400px;
    right: 0px;
  }

---
![bg opacity](./assets/gradient.jpg)

# <!--fit--> Trapped by the CLI

How your favorite cryptographic toolkit can fool you
Nullcon Goa 2025

<style scoped>a { color: #36c; }</style>

<!-- This is presenter note. You can write down notes through HTML comments. -->

---
![bg opacity](./assets/gradient.jpg)

## About me (1/2)

- Introduced to Open Source & Free Software around the end of the 90's
- CompSci studies
- CTO at Conostix S.A. Luxembourg - AS197692
- **LUNOG** founding member
- Member of the **BSides Luxembourg** revival team
- Conference workshops & talks

<span style="color:transparent"> ______ </span>![height:60px](assets/conostix.png)<span style="color:transparent"> ______ </span>![height:80px](assets/bsides.png)

<span style="color:transparent"> _______________________ </span>![height:100px](assets/lunog.png)

---
![bg opacity](./assets/dbc.jpg)

## About me (2/2)

- Open Source contributions:
    - **ssldump** improvements (build system, JSON output, IPv6 & ja3(s), . . .)
    - **asn1template**: painless ASN.1 editing from the CLI
    - **dispki**: one-shot disposable PKI
- **Qubes OS** user since R3.2
- 🎸 🏃 🚵 🔭 ⏚ . . .
- Contact info
    - GitHub: https://github.com/wllm-rbnt
    - Mastodon: https://infosec.exchange/@wr

---
![bg opacity](./assets/gradient.jpg)
## Outline

- X.509, PEM, DER & ASN.1 overview
- CVE-2022-0778 & cryptographic data structures editing
- The story behind this talk
- Experiments & findings
- Real world implications

---
![bg opacity](./assets/gradient.jpg)
# <!--fit--> X.509, PEM, DER & ASN.1 overview

---
![bg opacity](./assets/gradient.jpg)
<p style="text-align:center;">
An <span style="color:#4493F8;">X.509</span> certificate is an <span
style="color:#4493F8;">ASN.1</span> structure usually encoded as a <span
style="color:#4493F8;">DER</span> binary object maybe encapsulated in <span
style="color:#4493F8;">PEM</span> format
</p>

<p style="text-align:center;">
<span style="color:#4493F8;">PEM</span> format ? <span style="color:#4493F8;">DER</span> binary object ?? <span style="color:#4493F8;">ASN.1</span> structure ??!?!
</p>

---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## An X.509 certificate printed via the **openssl x509** command

```
$ echo | openssl s_client -connect google.com:443 | openssl x509 -text -noout
Certificate:                                                             
    Data:                                                                                                                                         
        Version: 3 (0x2)                                                                                                                          
        Serial Number:                                                                                                                            
            df:5b:69:1b:21:76:4a:32:12:1c:2f:37:8b:e5:96:d3                                                                                       
        Signature Algorithm: sha256WithRSAEncryption                                                                                              
        Issuer: C = US, O = Google Trust Services, CN = WR2                                                                                       
        Validity                                                                                                                                  
            Not Before: Jan 27 08:35:27 2025 GMT                                                                                                  
            Not After : Apr 21 08:35:26 2025 GMT                                                                                                  
        Subject: CN = *.google.com                                                                                                                
        Subject Public Key Info:                                                                                                                  
            Public Key Algorithm: id-ecPublicKey                                                                                                  
                Public-Key: (256 bit)                                                                                                             
                pub:                                                                                                                              
                    04:a0:26:86:48:d6:05:d9:37:36:b3:e3:d0:44:3e:                                                                                 
                    [...]
                    7b:85:b9:a8:7f                                                                                                                
                ASN1 OID: prime256v1                                                                                                              
                NIST CURVE: P-256                                                                                                                 
        X509v3 extensions:                                                                                                                        
            X509v3 Key Usage: critical                        
                Digital Signature                                        
            X509v3 Extended Key Usage:                        
                TLS Web Server Authentication                            
[...]
```

---
<!--
_class: smallcode
-->
![bg opacity](./assets/gradient.jpg)
## An X.509 certificate in PEM format 

```
$ echo | openssl s_client -connect google.com:443 | openssl x509
-----BEGIN CERTIFICATE-----
MIIOCjCCDPKgAwIBAgIRAN9baRshdkoyEhwvN4vlltMwDQYJKoZIhvcNAQELBQAw
OzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczEM
MAoGA1UEAxMDV1IyMB4XDTI1MDEyNzA4MzUyN1oXDTI1MDQyMTA4MzUyNlowFzEV
MBMGA1UEAwwMKi5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
oCaGSNYF2Tc2s+PQRD5kX2GInK49w1IBRF6Rf97ixqizgxIfA4GtZJZ5gAjk0SWH
gORZ+CvgnMUbyix7hbmof6OCC/YwggvyMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTmdR9tqDky5r2V
7LHRlNvVU4H4FDAfBgNVHSMEGDAWgBTeGx7teRXUPjckwyG77DQ5bUKyMDBYBggr
BgEFBQcBAQRMMEowIQYIKwYBBQUHMAGGFWh0dHA6Ly9vLnBraS5nb29nL3dyMjAl
BggrBgEFBQcwAoYZaHR0cDovL2kucGtpLmdvb2cvd3IyLmNydDCCCc0GA1UdEQSC
CcQwggnAggwqLmdvb2dsZS5jb22CFiouYXBwZW5naW5lLmdvb2dsZS5jb22CCSou
YmRuLmRldoIVKi5vcmlnaW4tdGVzdC5iZG4uZGV2ghIqLmNsb3VkLmdvb2dsZS5j
b22CGCouY3Jvd2Rzb3VyY2UuZ29vZ2xlLmNvbYIYKi5kYXRhY29tcHV0ZS5nb29n
bGUuY29tggsqLmdvb2dsZS5jYYILKi5nb29nbGUuY2yCDiouZ29vZ2xlLmNvLmlu
gg4qLmdvb2dsZS5jby5qcIIOKi5nb29nbGUuY28udWuCDyouZ29vZ2xlLmNvbS5h
[...]
6bVuRg8RIdWQi7fpCgqioGswTqeLIKzaALCxwKhXy4PaXLeU4FvEntM4n8Awbuk
0YOCzDtSjiFal8rSnOGbaorSymegOcfPhhrzm2UmPLUKEh2V+2BNi/9K2AdL/g==
-----END CERTIFICATE-----
```

---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## The PEM format

```
-----BEGIN CERTIFICATE-----                                              
MIIOCjCCDPKgAwIBAgIRAN9baRshdkoyEhwvN4vlltMwDQYJKoZIhvcNAQELBQAw
OzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczEM
MAoGA1UEAxMDV1IyMB4XDTI1MDEyNzA4MzUyN1oXDTI1MDQyMTA4MzUyNlowFzEV
MBMGA1UEAwwMKi5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
oCaGSNYF2Tc2s+PQRD5kX2GInK49w1IBRF6Rf97ixqizgxIfA4GtZJZ5gAjk0SWH
gORZ+CvgnMUbyix7hbmof6OCC/YwggvyMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTmdR9tqDky5r2V                                                                                  
7LHRlNvVU4H4FDAfBgNVHSMEGDAWgBTeGx7teRXUPjckwyG77DQ5bUKyMDBYBggr
BgEFBQcBAQRMMEowIQYIKwYBBQUHMAGGFWh0dHA6Ly9vLnBraS5nb29nL3dyMjAl
[...]
/4bgeLYcnWuE2oydoR9Vr/PpKGZcefWrb5oNu5Ttuui6VwD2edlM8IcVG+nOKFKH
bydJ2Ra5KFCmBmkFq8ZVi6zHlLdvk8B5qIeaq7VsRycPFsEUc9mjFI7gO4vBaHkc
gPzk
-----END CERTIFICATE-----
```
- <span style="color:#4493F8;">P</span>rivacy-<span style="color:#4493F8;">E</span>nhanced <span style="color:#4493F8;">M</span>ail
- IETF RFC 1421 and IETF RFC 7468
- Base64 + surrounding BEGIN/END tags
- Useful for transport of binary structures over text-based channels such as email

---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## The PEM format - Transport over text channels

Valid types (from openssl-format-options(1)):

```
RSA PUBLIC KEY              ECDSA PUBLIC KEY
X509 CERTIFICATE            ENCRYPTED PRIVATE KEY
DSA PRIVATE KEY             PARAMETERS
NEW CERTIFICATE REQUEST     PKCS #7 SIGNED DATA
ANY PRIVATE KEY             PKCS7
CERTIFICATE                 PRIVATE KEY
CERTIFICATE REQUEST         PUBLIC KEY
CMS                         RSA PRIVATE KEY
DH PARAMETERS               SSL SESSION PARAMETERS
DSA PARAMETERS              TRUSTED CERTIFICATE
DSA PUBLIC KEY              X509 CRL
EC PARAMETERS               X9.42 DH PARAMETERS
EC PRIVATE KEY
```

---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## DER binary encoding (1) - binary output

```
$ echo | openssl s_client -connect google.com:443 | openssl x509 -outform DER | hexdump -C
00000000  30 82 0e 0a 30 82 0c f2  a0 03 02 01 02 02 11 00  |0...0...........|
00000010  df 5b 69 1b 21 76 4a 32  12 1c 2f 37 8b e5 96 d3  |.[i.!vJ2../7....|
00000020  30 0d 06 09 2a 86 48 86  f7 0d 01 01 0b 05 00 30  |0...*.H........0|
00000030  3b 31 0b 30 09 06 03 55  04 06 13 02 55 53 31 1e  |;1.0...U....US1.|
00000040  30 1c 06 03 55 04 0a 13  15 47 6f 6f 67 6c 65 20  |0...U....Google |
00000050  54 72 75 73 74 20 53 65  72 76 69 63 65 73 31 0c  |Trust Services1.|
00000060  30 0a 06 03 55 04 03 13  03 57 52 32 30 1e 17 0d  |0...U....WR20...|
00000070  32 35 30 31 32 37 30 38  33 35 32 37 5a 17 0d 32  |250127083527Z..2|
00000080  35 30 34 32 31 30 38 33  35 32 36 5a 30 17 31 15  |50421083526Z0.1.|
00000090  30 13 06 03 55 04 03 0c  0c 2a 2e 67 6f 6f 67 6c  |0...U....*.googl|
000000a0  65 2e 63 6f 6d 30 59 30  13 06 07 2a 86 48 ce 3d  |e.com0Y0...*.H.=|
000000b0  02 01 06 08 2a 86 48 ce  3d 03 01 07 03 42 00 04  |....*.H.=....B..|
000000c0  a0 26 86 48 d6 05 d9 37  36 b3 e3 d0 44 3e 64 5f  |.&.H...76...D>d_|
000000d0  61 88 9c ae 3d c3 52 01  44 5e 91 7f de e2 c6 a8  |a...=.R.D^......|
000000e0  b3 83 12 1f 03 81 ad 64  96 79 80 08 e4 d1 25 87  |.......d.y....%.|
000000f0  80 e4 59 f8 2b e0 9c c5  1b ca 2c 7b 85 b9 a8 7f  |..Y.+.....,{....|
[...]
00000df0  8a d2 ca 67 a0 39 c7 cf  86 1a f3 9b 65 26 3c b5  |...g.9......e&<.|
00000e00  0a 12 1d 95 fb 60 4d 8b  ff 4a d8 07 4b fe        |.....`M..J..K.|
00000e0e
```

---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## DER binary encoding (2) - **openssl x509** command

```
$ echo | openssl s_client -connect google.com:443 | openssl x509 -outform d | openssl x509 -inform d -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            df:5b:69:1b:21:76:4a:32:12:1c:2f:37:8b:e5:96:d3
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Google Trust Services, CN = WR2
        Validity
            Not Before: Jan 27 08:35:27 2025 GMT
            Not After : Apr 21 08:35:26 2025 GMT
        Subject: CN = *.google.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:a0:26:86:48:d6:05:d9:37:36:b3:e3:d0:44:3e:
                    [...]
                    7b:85:b9:a8:7f
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
[...]
```

---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## DER binary encoding (3) - **openssl asn1parse** command

```
$ man openssl-asn1parse
[...]
NAME
    openssl-asn1parse, asn1parse - ASN.1 parsing tool
[..]
DESCRIPTION
    The asn1parse command is a diagnostic utility that can parse
    ASN.1 structures. It can also be used to extract data from ASN.1
    formatted data.
[...]
```

---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## DER binary encoding (4) - **openssl asn1parse** command

```
$ echo | openssl s_client -connect google.com:443 | openssl x509 -outform d | openssl asn1parse -inform d -i
    0:d=0  hl=4 l=3594 cons: SEQUENCE          
    4:d=1  hl=4 l=3314 cons:  SEQUENCE          
    8:d=2  hl=2 l=   3 cons:   cont [ 0 ]        
   10:d=3  hl=2 l=   1 prim:    INTEGER           :02
   13:d=2  hl=2 l=  17 prim:   INTEGER           :DF5B691B21764A32121C2F378BE596D3
   32:d=2  hl=2 l=  13 cons:   SEQUENCE          
   34:d=3  hl=2 l=   9 prim:    OBJECT            :sha256WithRSAEncryption
   45:d=3  hl=2 l=   0 prim:    NULL              
   47:d=2  hl=2 l=  59 cons:   SEQUENCE          
   49:d=3  hl=2 l=  11 cons:    SET               
   51:d=4  hl=2 l=   9 cons:     SEQUENCE          
   53:d=5  hl=2 l=   3 prim:      OBJECT            :countryName
   58:d=5  hl=2 l=   2 prim:      PRINTABLESTRING   :US
   62:d=3  hl=2 l=  30 cons:    SET               
   64:d=4  hl=2 l=  28 cons:     SEQUENCE          
   66:d=5  hl=2 l=   3 prim:      OBJECT            :organizationName
   71:d=5  hl=2 l=  21 prim:      PRINTABLESTRING   :Google Trust Services
   94:d=3  hl=2 l=  12 cons:    SET               
   96:d=4  hl=2 l=  10 cons:     SEQUENCE          
   98:d=5  hl=2 l=   3 prim:      OBJECT            :commonName
  103:d=5  hl=2 l=   3 prim:      PRINTABLESTRING   :WR2
[...]
```

---
![bg opacity](./assets/gradient.jpg)

## Binary Encodings for ASN.1
- <span style="color:#4493F8;">BER – Basic Encoding Rules</span>
- <span style="color:#4493F8;">DER – Distinguished Encoding Rules</span>
- CER – Canonical Encoding Rules
- XER – Basic XML Encoding Rules
- CXER – Canonical XML Encoding Rules
- EXER – Extended XML Encoding Rules
- OER – Octet Encoding Rules
- JER – JSON Encoding Rules
. . .

---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## ASN.1 Example – (grossly simplified) X.509 Certificate

```
Certificate  ::=  SEQUENCE  {
     tbsCertificate       TBSCertificate,
     signatureAlgorithm   AlgorithmIdentifier,
     signature            BIT STRING
}

TBSCertificate ::= SEQUENCE {
    version INTEGER,
    serialNumber INTEGER,
    signature AlgorithmIdentifier,
    issuer SEQUENCE of PrintableString,
    SEQUENCE {
        notBefore      UTCTime,
        notAfter       UTCTime
    }
    subject SEQUENCE of PrintableString,
    subjectPublicKeyInfo SubjectPublicKeyInfo,
    [...]
}
```

Reference: https://www.rfc-editor.org/rfc/rfc2459#page-15

---
![bg opacity](./assets/gradient.jpg)
## Abstract Syntax Notation One - ASN.1

- Interface Description Language (IDL)
- From https://en.wikipedia.org/wiki/ASN.1 : used to define data structures that
  can be serialized and deserialized in a cross-platform way
- ITU-T & ISO/IEC standard from the 80’s
- Used in PKCS, X.500, LDAP, Kerberos, SNMP, EMV, GSM, UMTS, LTE, 5G, . . .
- Our use case is the definition of <span style="color:#4493F8;">cryptographic data structures</span> such as X.509 certificates, RSA/EC keys, . . .
- Recommended reading:
  https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/

---
![bg opacity](./assets/gradient.jpg)
## ASN.1 Tags (serve as Types Identifiers)

<div class="columns">
<div>

### **Basic types (primitive)**

BOOLEAN
INTEGER
NULL
OID
UTCTIME, GENERALIZEDTIME
OCTET STRING
BIT STRING
UTF8String, PRINTABLESTRING, . . .
ENUM
</div>
<div>

### **Structured types (constructed)**

SEQUENCE, SEQUENCE OF
SET, SET OF
</div>
</div>

---
![bg opacity](./assets/gradient.jpg)
## ASN.1 Tag Classes (give Context Definition to Tags)

- Specify encoding instructions in order to remove ambiguity where necessary
- It helps defining our own tags using a class and a tag value
- Tags can be encoded using 1 byte, up to 6 bytes (uint < 2<sup>31</sup> − 1 max)
- Available classes are:
    <span style="color:#4493F8;">U</span>NIVERSAL (default), <span style="color:#4493F8;">A</span>PPLICATION, <span style="color:#4493F8;">C</span>ONTEXT SPECIFIC or <span style="color:#4493F8;">P</span>RIVATE
- Classes encoding can be IMPLICIT or EXPLICIT

---
![bg opacity](./assets/gradient.jpg)
## DER Encoded X.509 certificate

![height:20%](assets/asn1_der.png)

---
![bg opacity](./assets/gradient.jpg)
## BER/DER structure encodings

- Byte based binary formats
- **TLV** – <span style="color:#4493F8;">**T**</span>ype(aka Tag), <span style="color:#4493F8;">**L**</span>ength, <span style="color:#4493F8;">**V**</span>alue
- BER allows encoding of a given ASN.1 structure in multiple ways
- BER is useful for streams (content not known in advance)
- DER is a subset of BER along with canonicalization rules
- ⇨ DER only allows a single encoding for a given ASN.1 structure
- ⇨ That’s why it is used for signed data structures (fixed content)

---
<!--
_footer: ''
-->
![bg opacity](./assets/gradient.jpg)
## DER Tag & Class encoding (first byte)

<style scoped>
p { columns: 2; }
</style>

<span style="color:transparent"> ____ </span>![height:260px](assets/tags.png)<span style="color:transparent"> ______ </span>![height:170px](assets/classes.png)
IMPLICIT class encoding
<span style="color:transparent"> ____ </span>![height:130px](assets/tags_classes.png)
<span style="font-size:20px">• Bit <span style="color:#4493F8;">#5</span> indicates a Constructed tag Vs a Primitive tag</span>
<span style="font-size:20px">• Bits <span style="color:#4493F8;">#8</span> & <span style="color:#4493F8;">#7</span> are use for class encoding</span>
<span style="color:transparent"> ____ </span>
EXPLICIT class encoding
<span style="font-size:20px">• The tag in embedded into a surrounding SEQUENCE that holds the class encoding</span>

---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## DER TLV encoding example
```
my_struct ::= SEQUENCE {
    int0 INTEGER:0x12
    int1 INTEGER:0x34
}

 /--> type: SEQUENCE
 /  /--> length: 6 bytes
 /  /  
30 06     /--/--/-----/--/--/--> value: the two DER encoded INTEGERs
         02 01  /     /  /  /
          \  \ 12     /  /  /
          \  \  \    02 01  /
          \  \  \     \  \ 34
          \  \  \     \  \  \--> value: 0x34
          \  \  \     \  \--> length: 1 byte
          \  \  \     \--> type: INTEGER
          \  \  \
          \  \  \--> value: 0x12
          \  \--> length: 1 byte
          \--> type: INTEGER
```

---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## Parsing an encoded X.509 certificate with **openssl asn1parse**
```
$ echo | openssl s_client -connect google.com:443 | openssl x509 | openssl asn1parse -i
    0:d=0  hl=4 l=3594 cons: SEQUENCE          
    4:d=1  hl=4 l=3314 cons:  SEQUENCE          
    8:d=2  hl=2 l=   3 cons:   cont [ 0 ]        
   10:d=3  hl=2 l=   1 prim:    INTEGER           :02
   13:d=2  hl=2 l=  17 prim:   INTEGER           :DF5B691B21764A32121C2F378BE596D3
   32:d=2  hl=2 l=  13 cons:   SEQUENCE          
   34:d=3  hl=2 l=   9 prim:    OBJECT            :sha256WithRSAEncryption
   45:d=3  hl=2 l=   0 prim:    NULL              
   47:d=2  hl=2 l=  59 cons:   SEQUENCE          
[...]
   98:d=5  hl=2 l=   3 prim:      OBJECT            :commonName
  103:d=5  hl=2 l=   3 prim:      PRINTABLESTRING   :WR2
  108:d=2  hl=2 l=  30 cons:   SEQUENCE          
  110:d=3  hl=2 l=  13 prim:    UTCTIME           :250127083527Z
  125:d=3  hl=2 l=  13 prim:    UTCTIME           :250421083526Z
  140:d=2  hl=2 l=  23 cons:   SEQUENCE          
  142:d=3  hl=2 l=  21 cons:    SET               
  144:d=4  hl=2 l=  19 cons:     SEQUENCE          
  146:d=5  hl=2 l=   3 prim:      OBJECT            :commonName
  151:d=5  hl=2 l=  12 prim:      UTF8STRING        :*.google.com
[...]
```

---
![bg opacity](./assets/gradient.jpg)
# <!--fit--> CVE-2022-0778 & cryptographic data structure editing

---
![bg opacity](./assets/gradient.jpg)
## March 2022 - CVE-2022-0778 - OpenSSL Advisory

```
Severity
    High
Published
    15 March 2022
Title
    Infinite loop in BN_mod_sqrt() reachable when parsing certificates
Found by
    Tavis Ormandy (Google)
Affected versions
    OpenSSL
        from 3.0.0 before 3.0.2
        from 1.1.1 before 1.1.1n
        from 1.0.2 before 1.0.2zd
```
https://openssl-library.org/news/vulnerabilities/index.html#CVE-2022-0778

---
![bg opacity](./assets/gradient.jpg)
The first PoC was released:
    https://github.com/drago-96/CVE-2022-0778

```
The discovered vulnerability triggers an infinite loop in the function
BN_mod_sqrt() of OpenSSL while parsing an elliptic curve key. This means that a
maliciously crafted X.509 certificate can DoS any unpatched server.

The core of the vulnerability is in the parsing of EC keys with points in
compressed format:
[...]
```

## This PoC involves crafting a new X.509 certificate or modifying an existing one



---
<!--
_header: ''
_footer: ''
-->
![bg width:650px](./assets/asn1-structure-of-x509-before.png)
![bg width:650px grayscale:1](./assets/asn1-structure-of-x509-after.png)

---
<!--
_header: ''
_footer: ''
-->
![bg width:650px](./assets/asn1-structure-of-x509-before.png)
![bg width:650px](./assets/asn1-structure-of-x509-after.png)

---
<!--
_header: ''
_footer: ''
-->
# Editing DER files by hand is a pain
![bg width:650px](./assets/asn1-structure-of-x509-before.png)
![bg width:650px](./assets/asn1-structure-of-x509-after.png)

---
![bg opacity](./assets/gradient.jpg)
## **asn1template.pl** - my solution to this problem

```
$ man openssl-asn1parse
[...]
-genstr string, -genconf file
    Generate encoded data based on string, file or both
    using ASN1_generate_nconf(3) format. [...]
[...]
```

Presented at PTS 2023 and Hack.lu 2023 (as a Lightning Talk)
    https://github.com/wllm-rbnt/asn1template

---
![bg opacity](./assets/gradient.jpg)
## **asn1template.pl** - how it works

Internal structure of the script:
- Reads the output of the <span style="color:#4493F8;">asn1parse</span> OpenSSL app
<span style="color:transparent"> __ </span>(a <span style="color:#C21807;">representation</span> of the tree structure)
- Reconstructs the ASN.1 structure tree
- Traverses the tree recursively, depth-first
- and writes the <span style="color:#4493F8;">-genconf</span> compatible output <span style="color:#4493F8;">ASN1_generate_nconf(3)</span>
<span style="color:transparent"> __ </span>(a <span style="color:#C21807;">description</span> of the tree structure)
- First version written around 2010. <span style="color:#4493F8;">der-ascii</span> did not exist back then.
- Written in Perl, depends on the OpenSSL CLI utility only

---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## **openssl asn1parse** command & **asn1template.pl**
```
$ openssl asn1parse -in test.der -i -inform D                  
 0:d=0 hl=2 l= 18 cons: SEQUENCE
 2:d=1 hl=2 l=  8 cons:  SEQUENCE
 4:d=2 hl=2 l=  6 cons:   SEQUENCE
 6:d=3 hl=2 l=  4 prim:    INTEGER                :76543210
12:d=1 hl=2 l=  6 cons:  SEQUENCE
14:d=2 hl=2 l=  4 prim:   INTEGER                :01234567
```

```
$ asn1template.pl test.der | tee test.tpl
asn1 = SEQUENCE:seq1@0-2-18
[seq1@0-2-18]
field2@2-2-8 = SEQUENCE:seq2@2-2-8
field3@12-2-6 = SEQUENCE:seq3@12-2-6
[seq2@2-2-8]
field4@4-2-6 = SEQUENCE:seq4@4-2-6
[seq4@4-2-6]
field5@6-2-4 = INTEGER:0x76543210
[seq3@12-2-6]
field6@14-2-4 = INTEGER:0x01234567
```

---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## Using **openssl asn1parse -genconf**

```
$ openssl asn1parse -genconf test.tpl -out test_reconstructed.der
```
```
$ openssl asn1parse -in test_reconstructed.der -i -inform D
 0:d=0 hl=2 l= 18 cons: SEQUENCE
 2:d=1 hl=2 l=  8 cons:  SEQUENCE
 4:d=2 hl=2 l=  6 cons:   SEQUENCE
 6:d=3 hl=2 l=  4 prim:    INTEGER                :76543210
12:d=1 hl=2 l=  6 cons:  SEQUENCE
14:d=2 hl=2 l=  4 prim:   INTEGER                :01234567
```
```
$ diff test.der test_reconstructed.der
$ echo $?
0
```


---
<!--
_class: smallcode
_paginate: true
-->
![bg opacity](./assets/gradient.jpg)
## Editing the **template**

```
$ sed -i -e 's/INTEGER:0x01234567/PRINTABLESTRING:HELLO/' test.tpl
$ openssl asn1parse -genconf test.tpl -out test_reconstructed_2.der -i
 0:d=0  hl=2 l=  19 cons: SEQUENCE          
 2:d=1  hl=2 l=   8 cons:  SEQUENCE          
 4:d=2  hl=2 l=   6 cons:   SEQUENCE          
 6:d=3  hl=2 l=   4 prim:    INTEGER           :76543210
12:d=1  hl=2 l=   7 cons:  SEQUENCE          
14:d=2  hl=2 l=   5 prim:   PRINTABLESTRING   :HELLO
```
```
$ openssl asn1parse -in test_reconstructed.der -i -inform D
 0:d=0 hl=2 l= 18 cons: SEQUENCE
 2:d=1 hl=2 l=  8 cons:  SEQUENCE
 4:d=2 hl=2 l=  6 cons:   SEQUENCE
 6:d=3 hl=2 l=  4 prim:    INTEGER                :76543210
12:d=1 hl=2 l=  6 cons:  SEQUENCE
14:d=2 hl=2 l=  4 prim:   INTEGER                :01234567
```

---
![bg opacity](./assets/gradient.jpg)
# <!--fit--> The story behind this talk

---
![bg opacity](./assets/gradient.jpg)
<style scoped>
img[alt~="center"] {
  display: block;
  margin: 0 auto;
}
</style>
## Hack.lu 2024 ...

Would you present a lightning talk ?

![height:350px center](assets/hack_lu.png)

---
![bg opacity](./assets/gradient.jpg)
## Idea ! 💡

I remembered writing this in the README file of <span style="color:#4493F8;">asn1template</span>'s repository:

    "Line feeds in OCTET STRINGs break the conversion."

This happens because <span style="color:#4493F8;">asn1template</span> treats each line of asn1parse as a fully
contained item, line feeds being considered as the item separator.

<span style="color:transparent"> ____ </span>⇨  It's not always the case

---
![bg opacity](./assets/gradient.jpg)
## Idea ! 💡

Corpus of 1.7M X.509 Certificates:
<span style="color:transparent"> __ </span>https://github.com/johndoe31415/x509-cert-testcorpus

Example of broken structure:
```
[...]
  651:d=4  hl=2 l=  15 cons: SEQUENCE          
  653:d=5  hl=2 l=   3 prim:  OBJECT            :X509v3 Certificate Policies
  658:d=5  hl=2 l=   8 prim:  OCTET STRING      :AAAA
BBBB
  668:d=4  hl=2 l=  76 cons: SEQUENCE          
  670:d=5  hl=2 l=   3 prim:  OBJECT            :X509v3 CRL Distribution Points
  675:d=5  hl=2 l=  69 prim:  OCTET STRING      [HEX DUMP]:30433041A03FA03D863B68747470[...]
[...]
```

---
![bg opacity](./assets/gradient.jpg)
## Similar bug reported in 2021
![height:500px](assets/openssl_issue_Screenshot_2025-02-26_08-25-26.png)

---
![bg opacity](./assets/gradient.jpg)
# <!--fit--> Experiments & findings

---
![bg opacity](./assets/gradient.jpg)
## <u>Goal</u>: embed some ANSI art into text fields of a certificate

<span style="color:transparent"> ________________________ </span><span style="color:#4493F8;">Requirement</span> for this to work:
<span style="color:transparent"> __________________________ </span>    terminal escape sequences, control and Unicode 
<span style="color:transparent"> __________________________ </span>        characters must be <span style="color:#4493F8;">printed raw</span>
<span style="color:transparent"> ____________________________ </span>
<span style="color:transparent"> ________________________ </span> 2 approaches:
<span style="color:transparent"> __________________________ </span>   - use a CSR configuration file (cfr. <span style="color:#4493F8;">man openssl-req</span>)
<span style="color:transparent"> __________________________ </span>   - generate a binary structure from a template with a 
<span style="color:transparent"> ____________________________ </span>     <span style="color:#4493F8;">placeholder</span> of same length as implanted data,
<span style="color:transparent"> ____________________________ </span>     then replace in binary file directly (adjust signature)
<span style="color:transparent"> ____________________________ </span>
ANSI art source: https://github.com/erkin/ponysay 
![top-left height:400px](assets/squirrel_Screenshot_2025-02-20_23-00-53.png)


---
![bg opacity](./assets/gradient.jpg)
## Terminal Control Characters & Sequences

- Control Characters (cfr. man ascii)
- Control Sequence Introducer (CSI) ⇨  introduced by <span style="color:#4493F8;">^[</span>
- Operating System Command (OSC) ⇨  introduced by <span style="color:#4493F8;">^]</span>

References:
- https://en.wikipedia.org/wiki/ANSI_escape_code
- "Weaponizing Plain Text ANSI Escape Sequences as a Forensic Nightmare" by STÖK ⇨  https://www.youtube.com/watch?v=KD1jEIMSjA4

---
<!--
_class: smallcode
_paginate: true
--> 
![bg opacity](./assets/gradient.jpg)
## Control Characters

Control characters are the ones with hex value <span style="color:#4493F8;">less than 0x20</span> (cfr. <span style="color:#4493F8;">man ascii</span>)

```
Hex   Char                          Ctrl-Key
────────────────────────────────────────────
00    NUL '\0' (null character)     ^@
[...]
07    BEL '\a' (bell)               ^G
08    BS  '\b' (backspace)          ^H
09    HT  '\t' (horizontal tab)     ^I
0A    LF  '\n' (new line)           ^J
0B    VT  '\v' (vertical tab)       ^K
0C    FF  '\f' (form feed)          ^L
0D    CR  '\r' (carriage ret)       ^M
[...]
1B    ESC (escape)                  ^[
[...]
20    SPACE                        N/A 
```

Mainly used for <span style="color:#4493F8;">cursor movement</span>, but also the entry point for <span style="color:#4493F8;">Terminal Escape Sequences</span>

---
<!--
_class: smallcode
_paginate: true
--> 
![bg opacity](./assets/gradient.jpg)
## Terminal Escape Sequences


Terminal Escape Sequences are used for color changes, cursor movements, terminal configuration, ...

```
           /---------------------------> Regular text
           /   /-----------------------> Switch to reverse video & red (CSI sequence)
           /   /        /--------------> Red background & black text
           /   /        /   /----------> Reset escape sequence (CSI sequence)
           /   /        /   /     /----> Regular text
$ echo -e "xxx \e[7;31m yyy \e[0m zzz"
```
<span style="color:transparent"> __ </span>![height:50px](assets/redreverse_Screenshot_2025-02-25_07-38-17.png)

---
<!--
_class: smallcode
_paginate: true
--> 
![bg opacity](./assets/gradient.jpg)

## Finding #1

- Unicode is printed from text fields such as CN, OU, ... for recent versions of OpenSSL (>= 3.2.4 from current release set)
- As a side effect, control characters & terminal escape sequences are printed raw (unescaped)
- Works since PR #16583

```
commit 86cfd132ffc4f6198cc640a29c293850c0a59914
Date:   Sat Sep 11 13:56:28 2021 +0200

        Use -nameopt utf8 by default

 unsigned long get_nameopt(void)
 {
-   return (nmflag_set) ? nmflag : XN_FLAG_ONELINE;
+   return (nmflag_set) ? nmflag : XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_UTF8_CONVERT;
```

---
![bg opacity](./assets/gradient.jpg)
# <!--fit--> Demo  - ANSI art injected in CN

---
![bg opacity](./assets/gradient.jpg)
## ANSI art injection in CN field with OpenSSL 3.0.16
Control characters and escape sequences are espaced correctly
![height:450px](assets/openssl_3.0.16_cert_Screenshot_2025-02-26_08-40-18.png)

---
![bg opacity](./assets/gradient.jpg)
## ANSI art injection in CN field with OpenSSL 3.4.1 - it works !
![height:500px](assets/squirrel_openssl_3.4.1_Screenshot_2025-02-26_08-47-55.png)

---
![bg opacity](./assets/gradient.jpg)
## Text injection in CN field with OpenSSL 3.4.1

<span style="color:transparent"> _____________________________ </span> - When transposing this technique to text, what
<span style="color:transparent"> ______________________________ </span>   comes after the injection point is still printed
<span style="color:transparent"> _____________________________ </span> - But it does not happen with the ANSI art ?!?
<span style="color:transparent"> ______________________________ </span> 
<span style="color:transparent"> ____________________________ </span>
<span style="color:transparent"> ____________________________ </span>
<span style="color:transparent"> ____________________________ </span>
<span style="color:transparent"> ____________________________ </span>
<span style="color:transparent"> ____________________________ </span>
<span style="color:transparent"> _____________________________ </span> - A double signature is visible in this example
![top-left height:500px](assets/double_text_Screenshot_2025-03-01_20-03-58.png)

---
![bg opacity](./assets/gradient.jpg)
## Finding #2

Unfinished OSC sequence, on Gnome Terminal (& some others) stops the text output

```
$ echo -ne "bla\nbla\n" > bla
$ echo -ne "bli\nbli\n" > bli
$ cat bla <(echo -e "\e]") bli
bla
bla
$ cat bla <(echo -e "\e]") bli | grep bli
bli
bli
```

We can use that behavior to hide text output after the injected implant

---
![bg opacity](./assets/gradient.jpg)
## Text injection with termination in CN field with OpenSSL 3.4.1
<span style="color:transparent"> _____________________________ </span>
<span style="color:transparent"> ______________________________ </span>
<span style="color:transparent"> _____________________________ </span>
<span style="color:transparent"> ______________________________ </span> 
<span style="color:transparent"> ____________________________ </span>
<span style="color:transparent"> ____________________________ </span>
<span style="color:transparent"> ____________________________ </span>
<span style="color:transparent"> ____________________________ </span>
<span style="color:transparent"> ____________________________ </span>
<span style="color:transparent"> _____________________________ </span>
![top-left height:500px](assets/simple_Screenshot_2025-03-01_20-39-12.png)

---
![bg opacity](./assets/gradient.jpg)

## Finding #3
- Content appended to SAN DNS fields is copied verbatim
- Except that '\n' must be replaced by something visually equivalent such as '\v'
- This works on all version of OpenSSL I tested (>= 0.9.7m)

---
![bg opacity](./assets/gradient.jpg)
# <!--fit--> Demo - text injected in SAN

---
![bg opacity](./assets/gradient.jpg)
# <!--fit--> Real work implications

---
![bg opacity](./assets/gradient.jpg)

- Different results for different terminal emulators (with ASCII only, or Unicode support)
- Other SSL/TLS tookits also affected at various levels
- Also work with certificate requests . . .

---
![bg opacity](./assets/gradient.jpg)
# <!--fit--> Demo - Fake Certificate Request

---
![bg opacity](./assets/gradient.jpg)

## Was this technique ever used ?

Corpus of 50M+ (and counting) X.509 certificates from CIRCL's passive SSL project
![](assets/circl.png)
https://www.circl.lu/services/passive-ssl/

---
![bg opacity](./assets/gradient.jpg)

## Dataset size distribution histogram

![](assets/size_histo_Screenshot_2025-02-22_16-00-47.png)

---
![bg opacity](./assets/gradient.jpg)

## Certificate oddities

```
Subject: C=UK, ST=Glasgow, L=Glasgow, O=Bellrock Technology Ltd, CN=${ansible_eth0[ipv4][address]}
```

```
Subject: C=FR, ST=Seed, L=Power, CN=${ServiceName}.alpharatio.cc                             
```

```
Subject: C=NG, ST=Enugu, L=ENUGU, O=Graceland Group of Schools, CN={{gracelandcloud.com}} 
```

---
![bg opacity](./assets/gradient.jpg)

## Certificate oddities

```
1.3.6.1.4.1.24255.2.1: 
    {"uuid":"1b444eb0-6474-4162-a78e-5e22c76bfe00","service":"OUTSCAN"}
```

```
1.2.3.4.5.6.7.8.1: 
    {"attrs":{"hf.Affiliation":"health0","hf.EnrollmentID":"ipfs0-health0","hf.Type":"ipfs"}}
```

---
![bg opacity](./assets/gradient.jpg)

## Certificate oddities

```
Subject: C=NO, ST=molde, L=molde, O=stormtek, OU=stormtek, CN=owncloud01, emailAddress=eivind^G^G@trollhousing.no
```

```
X509v3 Authority Key Identifier: 
    keyid:61:2F:38:E5:73:CC:22:6B:BE:45:25:23:0B:DF:89:7A:3F:CB:41:66
    DirName:/C=US/ST=Kentuc\x08\x08\x08\x08\x08\x08\x08\x08\x08Kentuckey\x08\x08y
        /L=Lexinghto\x08\x08\x08ton/O=PRoj\x08\x08\x08rojh\x08i
        /CN=Rex Hall/emailAddress=mmufault@otm\x08\x08\x08hotmail.com
```

---
![bg opacity](./assets/gradient.jpg)

## Certificate oddities

```
            X509v3 Issuer Alternative Name: 
                0.,^...+..+.........8....-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: BCPG v1.38b04

lQPGBFcwpekBCADp7m4Z/FZHpkYPmXLo2/cuPd9wCUXFvrGas98HE0rhHhQ/apkU
TAu49tr4iV2ks7jZuP4zVA81Iob7Po+CWLD5kYcCU0PjCH3LpmFfxXiO+GhFqM4a
+KtnEFaDTi9PTBv++bhQ5ZmAAJG3Qte3Q1YTdD3uzXKEwKysSWvTGQ9RLbRp1Yo1
ZoXQzlHYinEBuWoEU2dgOeKhtvi8k52PSxbFkklf/GC0hZ+99tMnqzmS7Gl+csNJ
all/VnNoVN2JKHf8szaPMKpv2xTlStzl6lIMsdG5eswr0/Z7NqG2zsupnyn7bfPJ
[...]
```

---
![bg opacity](./assets/gradient.jpg)

## Certificate oddities

```
            X509v3 Subject Alternative Name: 
                DNESC[dESC^H^H, DNS:localhost, DNS:ip-172-31-19-174, 
                    DNS:xe7p-5jtg-6snv-lne4-wfug-oaqo-hqkn-44m2-s2a2-fsqi-pvnl-iqwm, 
                    IP Address:172.17.0.1, IP Address:34.252.55.170, 
                    IP Address:127.0.0.1, IP Address:172.31.19.174
```

```
Subject: C='', ST=^M"><zzz=zzz>;%x\, L=^M"><zzz=zzz>;%x\, O=^M"><zzz=zzz>;%x\, 
    OU=^M"><zzz=zzz>;%x\, CN=rbsec.net, emailAddress=^M"><zzz=zzz>;%x\
```

---
![bg opacity](./assets/gradient.jpg)
# <!-- fit --><span style="color:transparent"> ______ </span>Conclusion<!-- fit --><span style="color:transparent"> ______ </span>
## The decision to print terminal escape sequences should be a <span style="color:#4493F8;">conscious choice</span> made by the user

## ... in the mean time, you can still use <span style="color:#4493F8;">less</span> when in doubt

```
$ openssl x509 -text -noout -in certificate.pem | less
```

---
![bg opacity](./assets/gradient.jpg)
# <!-- fit --><span style="color:transparent"> ______ </span>Bonus demo<!-- fit --><span style="color:transparent"> ______ </span>

---
![bg opacity](./assets/gradient.jpg)
# <!-- fit --><span style="color:transparent"> ______ </span>Questions ?<span style="color:transparent"> ______ </span>

