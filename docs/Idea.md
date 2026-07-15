# ClutterHunter Idea

ClutterHunter is a private, evidence-based storage agent for Windows. A fast
WizTree-style analyzer builds the authoritative storage index. An on-device
Ollama model then queries bounded tools to explain storage and refine a cleanup
plan without receiving the full filesystem tree.

The first milestone is non-destructive. The policy engine classifies items as
`protected`, `review-required`, or `cleanup-candidate`; the model cannot promote
an item into a safer tier. Projects, personal files, installed applications,
encrypted/unknown containers, backups, and low-confidence items remain protected
or require review.

There is no Ring0 component, cloud AI, LAN model endpoint, or automatic file
mutation. See [ProductPlan.md](ProductPlan.md) for the complete product contract,
architecture, interfaces, and acceptance criteria.
