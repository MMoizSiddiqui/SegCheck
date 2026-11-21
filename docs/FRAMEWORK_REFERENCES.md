# Framework references and mapping boundary

The built-in connection templates are original SegCheck content, with limited
supporting mappings. They do not reproduce a framework, establish equivalence
between frameworks, or provide full control coverage.

| Template | Supporting reference | Source |
|---|---|---|
| Selected external source to CDE services | PCI DSS 4.0.1, 11.4.5 | https://www.pcisecuritystandards.org/document_library/ |
| Selected prohibited boundary connections | NIST SP 800-53 Rev. 5, SC-7 | https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final |
| Selected network-domain separation paths | ISO/IEC 27002:2022, 8.22 | https://www.iso.org/standard/75652.html |

PCI SSC explains segmentation's role in workstation scope at
https://www.pcisecuritystandards.org/faqs/1115/ . This is broader than a single
Guest-to-CDE scenario. The access matrix, actual source position and appropriate
assessment methodology determine the paths to examine.

The ISO control identifier/title were checked against the published standard's
preview supplied by the Gulf Standardization Organization:
https://gso-sims-preview-doc-aws.s3-eu-west-1.amazonaws.com/iso-iec-27002-2022-en.html .
No full standard text is included in this repository. The ISO template references
27002 guidance; it does not claim ISO/IEC 27001 certification or complete Annex A
coverage.

NIST explicitly cautions that crosswalks do not establish automatic equivalence.
Analysts must review each supporting relationship for their environment. Custom
policies can include additional explicit mappings through the existing schema.
