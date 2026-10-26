# Record an incident and its deadlines

Tell Fendkit when you became aware of an incident. It calculates deadlines
and writes drafts. You decide whether the event is reportable and submit
the reports to ENISA.
Legal timing was checked on **20 October 2026** against
[Article 14 of Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng)
and [Commission reporting guidance](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting).

## Start with the maker's awareness time

An actively exploited vulnerability and a severe incident affecting product
security are different incident types. An advisory listing alone does not
establish either. Supply the time you became aware. Logs or the current clock
cannot establish that time for you.

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
Without an explicit time the CLI proposes now and asks for confirmation.
When using an agent, give it your actual time. Records keep an IANA
time zone for display. Elapsed-hour deadlines remain correct across clock changes.

## Read the current deadlines

| Type | Early warning | Notification | Final report |
| --- | --- | --- | --- |
| Actively exploited vulnerability | Within 24 hours of awareness | Within 72 hours of awareness | Within 14 days after a fix or mitigation becomes available |
| Severe incident | Within 24 hours of awareness | Within 72 hours of awareness | Within one month after the incident notification |

The severe-incident final date uses the notification submission time when
recorded. Until you record submission, it calculates a provisional date from the
notification deadline. One month means a calendar month in the recorded zone, clamped to its
last day where needed. For an exploited vulnerability, the final deadline stays pending until you
record when a fix or mitigation became available. Article 14(8) also requires informing affected users
without undue delay, and where appropriate all users.

A fix or mitigation may already exist when you learn about exploitation.
Record its actual availability time with `fix-available --at`, even if it
precedes awareness. Fendkit preserves both times and calculates the final
report deadline from availability plus fourteen elapsed days, including when
that deadline is already past. Early warning and notification still use
awareness. This calculation follows Article 14(2)(c), checked on
21 October 2026 against the [official regulation, page 38](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32024R2847).
Check the current reporting guidance for your circumstances; Fendkit gives
no legal advice.

## Review, file, then record what happened

`cra/incidents/<id>/` contains `incident.yml`, `early-warning.md`,
`notification.md`, `final-report.md` and `user-notice.md`. Draft dates do not update
automatically. Use `incident show` for the
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
