# The CRA for plugin makers

Fendkit is a free, open-source CLI that prepares Cyber Resilience Act evidence
for software makers, like WordPress plugin and theme vendors who sell in the
EU. The Cyber Resilience Act (CRA) sets security and vulnerability-handling
requirements for software and hardware that is sold or otherwise made
available in the EU. This guide explains which role you may have under it and
what it asks for by when. It is not legal advice.

The legal statements and links were checked on **20 October 2026**.

## Decide your role

Article 3 says a manufacturer is someone who develops a product, or has it
developed, and markets it under their own name or trademark. A paid
downloadable plugin can put you in this role. A free licence alone does not
settle it. What matters is whether there is a commercial activity. The
interview asks whether you sell the plugin, whether there is a paid edition
and whether you sell support.

Article 2 excludes free and open-source software that is developed or
supplied outside a commercial activity. Donations and hosted-only offerings
are the unclear cases. Fendkit's questions record your decision. They are not
a legal ruling. A remote service can still count as part of the product when it is
remote data processing without which the product cannot work (Article 3).
See the
[Commission's non-binding guidance of 27 July 2026](https://digital-strategy.ec.europa.eu/en/library/commission-publishes-new-guidance-support-timely-cyber-resilience-act-implementation).

An open-source steward is a legal person that gives sustained support to
specific open-source products intended for commercial activities and helps
keep them viable. Article 24 gives stewards a lighter set of obligations.
Fendkit v0.1 records the role and runs the same checks as for a manufacturer.
It does not assess the Article 24 duties. See
[the Commission's open-source explanation](https://digital-strategy.ec.europa.eu/en/policies/cra-open-source).

## Which dates apply

Article 71 sets the main application date at **11 December 2027**.
Manufacturer reporting under Article 14 applies from **11 September 2026**.
Reporting by open-source stewards under Article 24(3) applies from
11 December 2027. See the
[Commission reporting guidance](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting).

## Prepare evidence for your product

Article 13 lists the manufacturer's duties, including a risk assessment and
due diligence for third-party components. Annex I Part II asks for records of
components and vulnerabilities, including a machine-readable software bill of
materials (SBOM). Annex II covers the information for users. Annex VII
describes the technical documentation. Annex V sets out the EU declaration of
conformity. Fendkit creates [draft documents](documents.md) for all of these,
and you complete them. It leaves the declaration unsigned and without an
issue date.

Article 13(8) ties the support period to the expected use of the product.
That is generally at least five years, unless the product is expected to be
used for less. Under Article 13(9), each security update has to stay
available for at least ten years after its release, or for the remaining
support period if that is longer. Choose your support period and explain it.

Classification depends on the **core function** of your product in Annex III
or IV. Using an authentication library does not make your whole plugin an
identity management product. Init shows the category lists. You choose, and
unknown is allowed. Important and critical classes can need a further
assessment, which Fendkit does not prepare. See the
[Commission conformity assessment guidance](https://digital-strategy.ec.europa.eu/en/policies/cra-conformity-assessment).

Do not assume that a standard named in a draft gives you a presumption of
conformity. That depends on a citation in the Official Journal under
Article 27. Check the current
[Commission standardisation information](https://digital-strategy.ec.europa.eu/en/policies/cra-standardisation)
before you rely on it.

Read [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng)
for the legal text and [the Commission overview](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
for implementation news. The first run on your own plugin is in the
[README](../README.md#start-on-your-plugin).
