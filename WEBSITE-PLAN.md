# NalaStrong Foundation website plan

Proposed public domain is NalaStrong.org. Proposed source repository is [NalaStrong on GitHub](https://github.com/jimjrxieb/NalaStrong). The first milestone is a private preview using sample data and family-approved copy.

## Public website

| Page | What visitors can do |
| --- | --- |
| Home | Read why NalaStrong exists and find Nala's story, family resources, and ways to help. |
| Nala's Story | Read a family-written account with approved photos and milestones. The family decides which names, dates, and medical details to share. |
| How We Help | Learn about proposed care baskets, water treatment, and HVAC UV installation assistance. Explain eligibility and availability once the board adopts them. Have qualified contractors evaluate home projects and describe the program without medical protection claims. |
| Donate | Give through a hosted checkout once fundraising is cleared. Explain how gifts are used and publish approved disclosures and acknowledgment language. |
| Impact and Contact | See aggregate program spending and support delivered. Provide a general contact address with a prompt to keep medical information out of messages. |

## Private staff portal

Use a separate authenticated admin application, provisionally at admin.NalaStrong.org. Start with individual staff accounts, MFA, and server-side role checks. Keep payment card details with the hosted checkout provider. Keep case records minimal and use internal case IDs in financial views wherever possible.

- **Donations and deposits** show gross gifts, fees, refunds, net deposits, processor references, and reconciliation status. Import read-only processor data and deduplicate records by processor transaction ID.
- **Assistance and expenses** record payee, internal case ID, purpose, program, amount, funding restriction, invoice, approver, payment reference, and reconciliation status.
- **Roles** give program staff authority to request assistance, a designated approver authority to review requests, finance authority to record payments and reconcile, and authorized board or audit reviewers read-only access to the records they need. Enforce approvals by a person other than the requester and log role changes.
- **Audit history** records who requested, approved, recorded, corrected, or reconciled a transaction and when. Use append-only history and record corrections as linked adjustments. Keep invoices and exports access-controlled and log downloads.
- **Accounting** remains the financial system of record. In the first release, an authorized person pays through the foundation's bank or accounting workflow. The portal records the external payment reference. Each month, reconcile processor settlements to deposits and expenses to bank and accounting records. Report discrepancies and preserve supporting documentation.

An example workflow is a program coordinator requests payment against a contractor invoice, a second person approves it, finance records the bank confirmation, and the reviewer can trace the full history. Adopt written eligibility, assistance limits, conflicts-of-interest, and records-retention policies before using this workflow with real cases.

## Rollout and acceptance

1. **Story preview.** Build the public pages with a family-approved story, test on mobile and keyboard, and review all public copy and photos. Keep payment collection disabled.
2. **Fundraising launch.** Confirm the legal entity, foundation bank account, processor onboarding, solicitation filings or applicable exemption, and approved donor disclosures. Test checkout, acknowledgment, refund, duplicate transaction handling, and settlement reconciliation with sandbox data before activation.
3. **Finance portal.** Test access denial, self-approval blocking, a sample vendor expense through approval and reconciliation, correction history, export permissions, and backup recovery with synthetic records before onboarding staff.

## Filing and fundraising references

Sunbiz handles Florida nonprofit incorporation. Confirm the separate FDACS charitable solicitation requirements before soliciting and have a nonprofit attorney or CPA review the organization's federal exemption path, online fundraising footprint, and receipt wording. Publish tax-deductibility language after its applicability is confirmed. [Sunbiz nonprofit filing instructions](https://dos.fl.gov/sunbiz/start-business/efile/fl-nonprofit-corporation/instructions), [FDACS solicitation guidance](https://www.fdacs.gov/Business-Services/Solicitation-of-Contributions), [IRS exemption guidance](https://www.irs.gov/publications/p557), [IRS contribution acknowledgment guidance](https://www.irs.gov/charities-non-profits/charitable-organizations/charitable-organizations-substantiation-and-disclosure-requirements).
