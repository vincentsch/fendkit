# Record an incident and its deadlines

Fendkit records your awareness time, calculates deadlines and writes drafts.
It does not decide whether an event is reportable or file with ENISA.
Legal timing was checked on **20 October 2026** against
[Article 14 of Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng)
and [Commission reporting guidance](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting).

## Start with the maker's awareness time

An actively exploited vulnerability and a severe incident affecting product
security are different incident types. An advisory listing alone does not
establish either. The maker supplies when they became aware; an agent must
not infer that time from logs or the current clock.

These examples use a fictional maker-supplied time. Run them only in a test
project, or replace the title, type and time with your actual record:

```bash
fendkit incident new --type exploited-vulnerability --title 'Active exploitation of shipped component' --aware '2026-10-20T10:00:00+02:00'
fendkit incident new --type severe-incident --title 'Product security incident' --aware '2026-10-20T10:00:00+02:00'
fendkit incident list
fendkit incident show inc-1
```

Use the ID printed by new rather than assuming `inc-1`. `--aware` accepts
RFC 3339 with an offset, or `YYYY-MM-DD HH:MM` in the local time zone.
Without an explicit time the CLI proposes now and requires confirmation;
agents must request the maker's actual time instead. Records keep an IANA
time zone for display. Elapsed-hour deadlines remain correct across clock changes.

## Read the current deadlines

| Type | Early warning | Notification | Final report |
| --- | --- | --- | --- |
| Actively exploited vulnerability | Within 24 hours of awareness | Within 72 hours of awareness | Within 14 days after a fix or mitigation becomes available |
| Severe incident | Within 24 hours of awareness | Within 72 hours of awareness | Within one month after the incident notification |

The severe-incident final date uses the notification submission time when
recorded. Until then it shows a provisional basis from the notification due
time. One month means a calendar month in the recorded zone, clamped to its
last day where needed. Vulnerability final reporting stays pending until fix
availability is recorded. Article 14(8) also requires informing affected users
without undue delay, and where appropriate all users.

## Review, file, then record what happened

`cra/incidents/<id>/` contains `incident.yml`, `early-warning.md`,
`notification.md`, `final-report.md` and `user-notice.md`. Draft text contains
fields to complete; it does not freeze deadlines. Use `incident show` for the
current timing after every update. Existing drafts stay untouched.

Check each draft against the current
[ENISA Single Reporting Platform guidance and live form](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp).
A person submits there. Only after filing, record its time locally:

```bash
fendkit incident submitted inc-1 --stage early-warning --at '2026-10-20T15:00:00+02:00'
fendkit incident submitted inc-1 --stage notification --at '2026-10-21T12:00:00+02:00'
fendkit incident fix-available inc-1 --at '2026-10-21T14:00:00+02:00'
fendkit incident submitted inc-1 --stage final --at '2026-10-22T12:00:00+02:00'
fendkit incident show inc-1
```

Replace the example times with recorded facts. Submitted stages no longer
contribute overdue actions, even if filed late. Outstanding overdue stages
fail check policy. `fix-available` starts the vulnerability final-report clock;
it does not submit a report. Optional `--advisory` must match saved findings.
Use [command help](reference/fendkit_incident.md) for flags and
[status items](status-items.md) for the resulting check. Drafts give no legal advice.
