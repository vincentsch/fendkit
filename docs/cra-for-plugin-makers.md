# The CRA for plugin makers

The Cyber Resilience Act sets product security and vulnerability-handling
requirements for software and hardware sold or otherwise made available in
the EU market. This guide is preparation help, not legal advice.
Legal statements and links were checked on **20 October 2026**.

## Decide your role

Under Article 3, a manufacturer develops a product, or has it developed,
and markets it under their own name or trademark. A paid downloadable plugin
can put you in this role. A free licence alone does not settle scope:
commercial activity matters. Record sales, paid editions and paid support
in the interview rather than guessing from the repository licence.

Article 2 excludes free and open-source software developed or supplied outside
a commercial activity. Donations and hosted-only offerings need a scope
review; the tool's questions are a record of your decision, not a legal ruling.
A remote service can still matter when it is a remote data processing solution
necessary for a product's function. See the
[Commission's non-binding guidance of 27 July 2026](https://digital-strategy.ec.europa.eu/en/library/commission-publishes-new-guidance-support-timely-cyber-resilience-act-implementation).

An open-source steward is a legal person providing sustained support for
specific open-source products intended for commercial activities and helping
keep them viable. Article 24 has a lighter set of obligations. v0.1 records
that role and runs the same checks; it does not assess Article 24 duties.
See [the Commission's open-source explanation](https://digital-strategy.ec.europa.eu/en/policies/cra-open-source).

## Keep the dates separate

Article 71 sets the main application date at **11 December 2027**.
Manufacturer reporting under Article 14 applies from **11 September 2026**.
Open-source steward reporting under Article 24(3) applies from 11 December
2027. See [Commission reporting guidance](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting).

## Prepare evidence for your product

Article 13 covers manufacturer duties, including risk assessment and due
diligence for third-party components. Annex I Part II calls for component
and vulnerability records, including a machine-readable software bill of
materials (SBOM). Annex II concerns user instructions; Annex VII describes
technical documentation. Annex V sets out the EU declaration of conformity.
Fendkit creates [draft documents](documents.md) for you to complete.
It leaves the declaration unsigned and without a final issue date.

Article 13(8) ties support to expected use, generally at least five years
unless expected use is shorter. Under Article 13(9), each security update
must stay available for at least ten years after release or the remaining
support period, whichever is longer. Choose and explain your support period.

Classification depends on your product's **core function** in Annex III or IV.
Using an authentication library does not make your whole plugin an identity
management product. Init shows the category lists. You choose; unknown is
allowed. Important and critical classes can require further assessment that
Fendkit does not prepare. See
[Commission conformity assessment guidance](https://digital-strategy.ec.europa.eu/en/policies/cra-conformity-assessment).

Do not assume that a standard mentioned in a draft gives a presumption of
conformity. That depends on the applicable Official Journal citation under
Article 27; check the current
[Commission standardisation information](https://digital-strategy.ec.europa.eu/en/policies/cra-standardisation)
before relying on it.

Read [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng)
for the legal text and [the Commission overview](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
for current implementation information. Start with the
[README quickstart](../README.md#start-on-your-plugin), then use
[status items](status-items.md) to decide what needs attention.
