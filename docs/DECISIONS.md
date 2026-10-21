# Decision levels for Ten98 sessions

Make each decision at the lowest level that has both the authority and the facts. Escalate only with a brief, and record every decision where the next session will find it.

## Levels

| Level | Who | Decides | Records it in |
|---|---|---|---|
| L0 | App owner session (Campaign, Discover, Design System Main Sessions) | Anything inside an approved scope that can be reversed in under about a day: implementation, refactors, test design, local bug fixes, composing screens from `@ten98/ui`, choosing between licence-compatible upstream code to port for an approved feature. | Commit or PR description |
| L1 | Manager (Code System Main Session) | Coordination across sessions: Docker leases, release sequencing and pins, library promotion, routing gaps to library owners, branch and migration tactics within an approved plan, enforcing the standards. | Message to the owner; a GitHub comment when it changes a plan |
| L2 | Decision council (Code System Decision Sessions) | High-level questions: architecture and stack, cross-app contracts and data models, security and tenancy semantics, migration strategy, product scope and vision trade-offs, priorities across apps, and anything costing more than about a week to reverse. Also any L1 question the manager is unsure about. | Issue labelled `decision` in ten98-code-system |
| L3 | The user, through the manager | Anything irreversible or outward: production deploys and data cutovers, spending or paid provider calls, licences and legal terms, repository visibility, account, credential and security settings, deleting user data, changes to the user's own standards, and product-direction reversals. | The user's words, quoted, on the decision issue |

A security risk goes straight to the manager at any level. Owners never wait on L2 for L0 work.

## Brief (owner or manager → council), at most 400 words

1. **Question.** One sentence, answerable with a decision.
2. **Purpose.** Why the app or feature exists, and which goal this decision serves.
3. **Deadline.** What is blocked, and from when.
4. **Options.** Two to four, including "do nothing" and, where one exists, "port upstream". Give each one's cost and risk.
5. **Constraints.** Standards, contracts and user decisions that apply, each with a link.
6. **Evidence.** File:line references, measurements and links. No pasted logs.
7. **Asker's recommendation**, and how hard it would be to reverse.

## Record (council → manager), at most 300 words

- **Decision**, plus the level that must approve it if it is L3.
- **Rationale**, traced back to the purpose.
- **Options rejected**, each with a one-line reason.
- **Risks and mitigations**, including a short pre-mortem: if this fails in six months, why?
- **Reversal trigger.** The evidence that would make us revisit it.
- **Confidence** (high, medium or low), and the next step for the owner.

## Council rules

- Answer only. Never edit, commit, install or push anything. Read at most five referenced files per decision, and only the lines cited.
- Spend at most 10 minutes per decision. If the brief lacks the facts, return the missing questions instead of guessing.
- Consider every option, the effect on all apps, second-order effects and the reversal trigger, within that time box.
- After about 10 decisions, or at about 60% context, hand off to the next numbered decision session with the open-decision list.
- Revisit a past decision when its reversal trigger fires, or at the end of its milestone. Record the outcome on the same issue.
