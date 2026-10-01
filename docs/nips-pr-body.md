# nips PR submission package — draft (not submitted)

Status: ready for human review. Actual PR submission requires the human collaborator's
confirmation and is done from the NoorMuse GitHub account (§26.6).

## What the nips repo actually requires (verified 2026-10-01)

Read directly from https://github.com/nostr-protocol/nips (README + repo
file listing; no PR/issue pages opened):

- **No NIP template file exists.** There is no TEMPLATE.md, CONTRIBUTING.md,
  or .github directory. A new NIP is a new `<NN>.md` file following the shape
  of existing ones.
- **No documented number-assignment process.** The README says nothing about
  who picks the number. Observed convention: the proposer picks an unused
  number as the filename; past 99 the repo uses two-digit hex (5A, 7D, A0,
  A3, A4, B0, B7, BE, C0, C7, CC, EE, F4). Highest listed is F4, so **F5**
  is the natural proposal. Maintainers may renumber at review.
- **No documented "issue first" requirement.** The process is: write the
  document, submit it to the repository as a PR, receive feedback, codify on
  rough consensus ("How this repository works").
- **The README's NIP list table needs a new row** for the accepted NIP (add
  it in the PR).
- NIPs are public domain (README "License").

## Why this PR is honest-but-weak (read before submitting)

The nips README's "Criteria for acceptance in this repository":

1. **Should be fully implemented in at least two clients and one relay** — when applicable.
2. Should make sense.
3. Should be optional and backwards-compatible.
4. No more than one way of doing the same thing.
5. Other rules will be made up when necessary.

**Criterion 1 is NOT met.** nakama has one working implementation (the
`nakama.py` CLI, offline-tested). It runs on unmodified relays (standard
EVENT/REQ), so "one relay" is trivially satisfied, but "two clients" is not.
The README itself says standards may exist as pull requests for discussion,
so submitting as a documentation/discussion PR is legitimate — but the PR body
must say this plainly. Expect the PR to sit as discussion, or be closed with
"come back when two clients implement it". That is a fine outcome: the PR
serves as a collision-avoidance marker for kinds 30107–30111.

Criteria 2–4 are satisfied: the document describes only event shapes
(clients that don't care ignore the kinds — optional), it introduces no new
relay behavior (backwards-compatible), and it does not duplicate an existing
NIP's job.

## Suggested PR title

```
NIP-F5: nakama protocol event kinds (30107–30111)
```

## Suggested PR body (paste verbatim, fill in the doc link)

---

This PR proposes a new NIP documenting the Nostr event shapes used by the
**nakama protocol** — a minimal, verifiable vocabulary for persistent
relationships between AI agent operators:

- `30107` — revocation (bond dissolution)
- `30108` — key-compromise-declaration
- `30109` — rotation certificate (identity move, signed by old key)
- `30110` — finalized board decision (threshold governance record)
- `30111` — draft decision (pre-decision circulation)

All five are *parameterized replaceable* (NIP-01, kinds 30000–39999). The NIP
fixes tags, content shape, signer, and canonical slot, plus a three-phase
verification rule. It does not define the bond protocol itself.

Honest status, since this repo cares about it:

- **Pre-registration remap:** the draft originally targeted 30100–30104. The
  existing-adoption survey (documented in §6 of the draft) found all five in
  use by unrelated apps, so the protocol moved to 30107–30111 *before any
  nakama event was ever published* — a clean cut, nothing republished.
- **Criterion 1:** there is one working implementation (a Python CLI,
  offline-tested). Two-client adoption is not there yet. Submitting this as a
  documentation record and collision-avoidance marker for community
  discussion, per the README's note that standards may exist as PRs. Close it
  if the consensus is "come back later" — the record will have served.
- The 30000–39999 namespace is public; this claims no exclusivity, only
  documentation so clients can parse, verify, and display these events.

Proposing number F5 (next available per the repo's numbering convention);
happy to renumber at reviewer request.

Reference implementation / full protocol spec:
https://github.com/NoorMuse/nakama-protocol

---

## Submission checklist

- [ ] the human collaborator confirms: submit this PR from the NoorMuse GitHub account
- [ ] Fork `nostr-protocol/nips`, branch e.g. `nip-f5-nakama-kinds`
- [ ] Copy `docs/NIP-nakama.md` → `F5.md`; replace the `NIP-F5` title
      placeholder if a maintainer renumbers
- [ ] Add a row for NIP-F5 to the README NIP list table
- [ ] Open the PR with the title/body above; link the reference repo
- [ ] Respond to reviewer feedback (renumber file if asked, adjust
      wording); do not argue for exclusivity over the kind block
- [ ] Record the outcome in spec §26 (accepted / rejected / no response);
      if accepted, update `docs/NIP-nakama.md` title and the kind notes
- [ ] If rejected or silent: keep this package as the collision marker and
      move on — no re-submission spam

## What NOT to do

- Do not claim the kind block 30107–30111 as exclusive property.
- Do not submit from an agent-owned throwaway account; the NoorMuse account
  is the human-created channel and reviews may ask follow-up questions only a
  human can answer well.
- Do not renumber kinds without a new existing-adoption survey (§26.4).
