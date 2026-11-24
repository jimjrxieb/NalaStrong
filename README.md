# NalaStrong

Read the [website plan](WEBSITE-PLAN.md) for the public site, fundraising rollout, and finance portal requirements.

- Open [the public website preview](preview/index.html) locally to see the proposed homepage and story page.
- Open [the staff prototype](staff-prototype/index.html) locally to review sample donation, payout, and audit records.

The public preview is static. The staff prototype uses synthetic records and has no authentication or payment access. Keep the staff prototype outside the public deployment. Keep private family records and financial documents outside this source tree.

## Run the local application

From this directory, use Python 3.11 or newer. Create local accounts with distinct passwords when prompted.

```sh
python3 app.py add-staff sample-program program
python3 app.py add-staff sample-approver approver
python3 app.py add-staff sample-finance finance
python3 app.py add-staff sample-reviewer reviewer
python3 app.py serve
```

Each `add-staff` prints an authenticator setup key. Add it to an authenticator app; sign-in requires the password and the current 6-digit code. Use `python3 app.py enroll-mfa <username>` to issue a new key, which also ends that user's sessions. Accounts created before MFA existed must run `enroll-mfa` before they can sign in. Five failed sign-ins lock a username for 15 minutes.

The session cookie is marked `Secure`. Chrome, Edge, and Firefox accept it on `http://127.0.0.1`; Safari may not, so use one of those for local testing.

## Run the tests

```sh
python3 -m unittest discover -s tests -v
```

The suite covers the payout workflow's misuse cases: role checks, skipped approvals, self-approval, duplicate bank references, append-only audit history, CSRF, origin and host checks, session expiry and logout, MFA, code replay, and lockout. It also covers the local family-photo route: only `nala-[1-9].jpg` files are served, path traversal returns 404, and only the homepage gets the script and image allowances. `.github/workflows/break-tests.yml` runs it on every pull request once this folder is the root of the NalaStrong repository.

Open http://127.0.0.1:8000/ for the public pages and http://127.0.0.1:8000/staff for staff sign-in. Use synthetic data. Program staff submit a request, an approver reviews it, finance records a sample external payment reference, and a reviewer reconciles it. SQLite stores the records and audit events under the ignored `.local/` directory.

The local server is for development. The production scope includes managed identity with MFA, HTTPS, controlled reports and backups, processor integration, accounting reconciliation, and a production deployment. Live donation and bank access are outside this local build.

## Security pipeline

`.github/workflows/security.yml` runs on every pull request, every push to `main`, and nightly:

| Check | Tool | Blocks the PR on |
| --- | --- | --- |
| `secrets-scan` | gitleaks, full git history | Any secret |
| `sast-scan` | Semgrep (Python, JavaScript, secrets, Actions rules) and Bandit | Semgrep ERROR, Bandit HIGH |
| `dependency-scan` | Trivy filesystem scan (vulnerabilities, secrets, misconfigurations) | CRITICAL |
| `workflow-scan` | zizmor | HIGH |

Lower-severity findings appear in each job summary. Reports are kept as 90-day workflow artifacts. Scanner versions are pinned in the workflow's `env` block, and downloaded binaries are checked against SHA-256 checksums. To make the checks mandatory, mark `test` (from `break-tests.yml`), `secrets-scan`, `sast-scan`, `dependency-scan`, and `workflow-scan` as required status checks in `main` branch protection.
