# Incidents and deadlines

Fendkit is a free, open-source CLI that helps software makers with their
Cyber Resilience Act duties. When your product is hit by an actively
exploited vulnerability or a severe incident, you tell Fendkit when you became
aware of it. It calculates the reporting deadlines and writes the drafts. You
decide whether the event is reportable, and you submit the reports to ENISA
yourself.

The legal timing was checked on **20 October 2026** against
[Article 14 of Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng)
and the [Commission reporting guidance](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting).

## Start with the maker's awareness time

An actively exploited vulnerability and a severe incident that affects the
security of your product are two different incident types. An advisory alone
is neither. Give Fendkit the time you became aware. A log or the current
clock cannot establish that time for you.

The examples use a fictional time. Run them in a test project only, or
replace the title, the type and the time with your own record:

```bash
fendkit incident new --type exploited-vulnerability --title 'Active exploitation of shipped component' --aware '2026-10-20T10:00:00+02:00'
fendkit incident new --type severe-incident --title 'Product security incident' --aware '2026-10-20T10:00:00+02:00'
fendkit incident list
fendkit incident show inc-1
```

Use the ID that `new` prints instead of assuming `inc-1`. `--aware` takes
RFC 3339 with an offset, or `YYYY-MM-DD HH:MM` in your local time zone.
Without a time, the CLI proposes now and asks you to confirm. When an agent
runs the command for you, give it the time you became aware. The record keeps an IANA
time zone for display. Deadlines count elapsed hours, so a clock change does
not shift them.

## Read the current deadlines

| Type | Early warning | Notification | Final report |
| --- | --- | --- | --- |
| Actively exploited vulnerability | Within 24 hours of awareness | Within 72 hours of awareness | Within 14 days after a fix or mitigation becomes available |
| Severe incident | Within 24 hours of awareness | Within 72 hours of awareness | Within one month after the incident notification |

For a severe incident, the final date counts from the time you recorded the
notification as submitted. Until then, Fendkit calculates a provisional date
from the notification deadline. One month means a calendar month in the
recorded zone, cut back to the last day of the month where needed. For an
exploited vulnerability, the final deadline stays pending until you record
when a fix or mitigation became available. Article 14(8) also asks you to
inform the affected users without undue delay, and where appropriate all
users.

A fix or mitigation may already exist when you learn about the exploitation.
Record the time it became available with `fix-available --at`, even when it
is before the awareness time. Fendkit keeps both times and calculates the
final report deadline as availability plus fourteen elapsed days, even when
that deadline has already passed. The early warning and the notification
still count from awareness. This follows Article 14(2)(c), checked on
21 October 2026 against the
[official regulation, page 38](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32024R2847).
Check the current reporting guidance for your case. Fendkit gives no legal
advice.

## After you filed

`cra/incidents/<id>/` holds `incident.yml`, `early-warning.md`,
`notification.md`, `final-report.md` and `user-notice.md`. The dates in the
drafts do not update by themselves. Run `incident show` for the current
timing after each update. Existing drafts stay untouched.

Check each draft against the current
[ENISA Single Reporting Platform guidance and live form](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp).
A person submits there. Only after you filed, record the time locally:

```bash
fendkit incident submitted inc-1 --stage early-warning --at '2026-10-20T15:00:00+02:00'
fendkit incident submitted inc-1 --stage notification --at '2026-10-21T12:00:00+02:00'
fendkit incident fix-available inc-1 --at '2026-10-21T14:00:00+02:00'
fendkit incident submitted inc-1 --stage final --at '2026-10-22T12:00:00+02:00'
fendkit incident show inc-1
```

Replace the example times with what happened. A stage recorded as submitted
no longer counts as overdue, even when you filed late. An overdue stage that
is still outstanding fails the check policy. `fix-available` starts the final
report clock for an exploited vulnerability. It does not submit anything. The
optional `--advisory` has to match a saved finding. See the
[command help](reference/fendkit_incident.md) for the flags and
[status items](status-items.md) for the resulting check.
