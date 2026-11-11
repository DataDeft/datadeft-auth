# Feature justification

Every feature must pass this review **before implementation begins**. Start with
an established requirement, not a mechanism or a hypothetical architecture.
This applies across libraries, bindings, adapters, examples, and infrastructure;
optional features and security hardening are not exempt.

## Required questions

| Question | Required answer |
| --- | --- |
| What problem exists? | A concrete user need, operational issue, or security threat—not a hypothetical architecture. |
| What already handles it? | Check existing code and infrastructure first. |
| Why isn't the current behavior sufficient? | Identify the actual gap. "Do nothing" must be a valid outcome. |
| What is the smallest solution? | Prefer existing configuration or integration guidance over new mechanisms. |
| What does it cost? | APIs, configuration, dependencies, migrations, operational burden, and security implications. |
| How will we prove it works? | Explicit acceptance criteria and tests. |

Name the affected consumer or workflow and cite the relevant requirement,
existing implementation, or threat model. Distinguish confirmed requirements
from assumptions and hypothetical examples. A concrete security threat model
can justify preventive work; observed exploitation is not required.

Consider doing nothing, using existing capabilities, and changing application
integration before adding library behavior. Account for the ongoing cost of
maintaining and operating the feature, not just the initial implementation.
Tests establish correctness against a requirement; they do not establish that
the feature is needed.

## Decision gate

1. Record answers to all six questions in the feature's issue, design document,
   or PR proposal. Keep the detail proportional to the change; a short answer
   per question is enough for a small feature.
2. Recommend the smallest justified scope, or recommend deferring or rejecting
   the feature. State assumptions and unresolved questions explicitly.
3. Obtain approval from the project owner or an explicitly delegated approver
   for that justification and scope **before coding**. Inclusion in a roadmap,
   a release plan, or an agent work assignment is not sufficient approval.
4. Revisit the decision if implementation introduces a new mechanism, broadens
   the scope, or materially changes the costs or security assumptions.
5. Before merge, confirm the implementation stays within the approved scope
   and meets its acceptance criteria. Technical checks and cross-crate API
   review remain required; they do not replace feature justification.

Apply the same lens to features already in progress before merging them.
Existing implementation effort is not evidence that a feature should be kept.
If the need cannot be established, stop and propose removal or deferral rather
than inventing a use case to justify the code.

## Proposal template

```text
Feature:
Problem and affected consumer/workflow:
Evidence or concrete threat model:
Existing code/infrastructure:
Gap in current behavior:
Alternatives, including doing nothing:
Smallest proposed solution and non-goals:
Costs (APIs, config, dependencies, migration, operations, security):
Acceptance criteria and tests:
Assumptions and open questions:
Recommendation (implement / defer / reject):
Approval (approver, agreed scope, and decision reference):
```
