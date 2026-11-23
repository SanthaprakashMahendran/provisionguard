# ProvisionGuard

A GitHub Action that reviews Terraform pull requests **before anyone approves them**. It runs `terraform plan`, checks the result, and posts one comment on the pull request that answers "is this safe to merge?".

The comment starts with a **verdict** (🔴 not ready, 🟡 review first, 🟢 looks good) decided by fixed rules, and a scorecard with one line per check:

| Check | What it tells you |
|---|---|
| 🔒 Security | Findings from Checkov, Trivy and/or KICS, ranked high/medium/low and explained in plain English by Claude |
| 💥 Existing infrastructure | Names already taken in AWS, and changes that would update, replace or delete existing resources, with what depends on them |
| 📊 Service quotas | Current account usage plus this change, against the AWS limits |
| 📏 Right-sizing | Resources larger than their environment allows, with the monthly saving |
| 🏷️ Tagging | Missing or invalid required tags, with suggested values |
| 💰 Cost | Estimated monthly cost per resource, from AWS list prices |
| 🗺️ Architecture | A diagram of what the change builds or modifies |

Every push to the pull request updates the same comment. ProvisionGuard only **reads** from AWS; it never runs `terraform apply`.

## How it works

1. A pull request is opened or updated in your Terraform repository.
2. Your workflow calls this action. GitHub starts a temporary machine, checks out your code and downloads this action.
3. If the pull request changes nothing under your Terraform folder, `policy/` or `provisionguard.yaml`, it stops there.
4. Otherwise it logs in to AWS with a read-only role, runs `terraform plan`, runs the security scanners, and runs each check on the plan.
5. Claude (optional) explains the security findings and draws the diagram; the verdict is always rule-based.
6. It posts the review as a comment. The machine is then deleted.

Nothing is copied into your repository: the only thing you add is one workflow file.

## Repository structure

```
provisionguard/
├── action.yml                  The action: its inputs, outputs and the steps it runs
├── pyproject.toml              Python package: dependencies (boto3, pyyaml), Python 3.9+, bundled policies
├── provisionguard/             The Python code
│   ├── main.py                 Entry point: runs every check and posts the review
│   ├── changes.py              Skips pull requests that don't touch Terraform
│   ├── config.py               Reads provisionguard.yaml and finds the policies
│   ├── plan_parser.py          Reads the terraform plan
│   ├── security.py             Security section (with scanners.py, which reads each scanner's output)
│   ├── existing.py             Existing infrastructure section
│   ├── quotas.py               Service quotas section
│   ├── rightsizing.py          Right-sizing section
│   ├── tagging.py              Tagging section
│   ├── cost.py                 Cost section (with pricing.py, which looks up AWS prices)
│   ├── diagram.py              Architecture section
│   ├── ai.py                   The only file that talks to the AI model
│   ├── aws.py                  Shared helpers for the read-only AWS calls
│   ├── report.py               Builds the comment: verdict, scorecard, sections
│   ├── github_comment.py       Creates or updates the comment on the pull request
│   └── policies/               Default right-sizing and tagging policies
├── tests/                      Unit tests, with sample plans and fake AWS responses
├── examples/
│   └── terraform-review.yml    Workflow to copy into your repository
└── .github/workflows/
    └── test.yml                Runs the tests on every change to this repository
```

## Setup

You need a GitHub repository with Terraform for AWS. Setup takes three steps.

### 1. Give GitHub Actions read-only access to AWS

Once per AWS account, in the IAM console:

1. **Identity provider:** if *Identity providers* doesn't already list `token.actions.githubusercontent.com`, add it: *Add provider* → *OpenID Connect*, provider URL `https://token.actions.githubusercontent.com`, audience `sts.amazonaws.com`.
2. **Role:** *Roles* → *Create role* → *Web identity*. Choose that provider, audience `sts.amazonaws.com`, and your GitHub organization and repository. Attach `ReadOnlyAccess` and name the role, e.g. `provisionguard-ci`.
3. **Trust policy:** open the role → *Trust relationships* → *Edit trust policy*, and replace it with the policy below. The one the console creates doesn't include GitHub's numeric IDs, so the login would be refused.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:<OWNER>@<OWNER_ID>/<REPO>@<REPO_ID>:pull_request"
      }
    }
  }]
}
```

Get `<OWNER_ID>` and `<REPO_ID>` with `gh api repos/<OWNER>/<REPO> --jq '.owner.id, .id'`. For a public repository, `https://api.github.com/repos/<OWNER>/<REPO>` in a browser shows them too.

### 2. Add repository secrets

In your repository: *Settings* → *Secrets and variables* → *Actions*:

| Secret | Value |
|---|---|
| `AWS_ROLE_ARN` | The role's ARN |
| `CLAUDE_CODE_OAUTH_TOKEN` | Optional. From `claude setup-token` with a Claude Pro or Max account; enables the AI assessment and the diagram |

### 3. Add the workflow

Save this as `.github/workflows/terraform-review.yml` (a commented copy is in [`examples/`](examples/terraform-review.yml)):

```yaml
name: Terraform review
on: pull_request

permissions:
  contents: read
  pull-requests: write # post the review comment
  id-token: write      # log in to AWS without stored keys

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: SanthaprakashMahendran/provisionguard@v1
        with:
          terraform-dir: infra # your Terraform folder
          aws-role-arn: ${{ secrets.AWS_ROLE_ARN }}
          claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
```

Open a pull request that changes the Terraform, and the review appears as a comment.

## Configuration

Everything below is optional.

### Inputs

| Input | Default | Purpose |
|---|---|---|
| `terraform-dir` | `infra` | Folder with the Terraform code |
| `aws-role-arn` | | Role to assume. Leave empty if an earlier step already set up AWS credentials |
| `aws-region` | `us-east-1` | Region for AWS calls when the code doesn't set `aws_region` |
| `terraform-version` | `1.9.8` | Terraform version for the plan |
| `terraform-init-args` | | Extra `terraform init` arguments, e.g. backend settings. `{account_id}` is replaced with the AWS account ID |
| `terraform-plan-args` | | Extra `terraform plan` arguments, e.g. `-var-file=prod.tfvars` |
| `scanners` | | `checkov`, `trivy`, `kics`, comma-separated. Overrides `provisionguard.yaml` |
| `config` | `provisionguard.yaml` | Path to the settings file |
| `claude-code-oauth-token` | | Enables the AI assessment and the diagram |
| `github-token` | `github.token` | Token used to post the comment |
| `skip-unchanged` | `true` | Skip pull requests that change nothing relevant. `false` reviews every one |
| `fail-on` | `never` | Fail the check on `caution` (red) or `warning` (yellow or red). With branch protection, this blocks merging |

**Outputs:** `verdict` (`caution`, `warning` or `ok`) and `reviewed` (`true` or `false`).

### Settings file

`provisionguard.yaml` in the root of your repository:

```yaml
security:
  scanners: [checkov, trivy]   # any of: checkov, trivy, kics (default: checkov)

policies:                      # only if your policies aren't in policy/
  rightsizing: rules/sizes.yaml
  tagging: rules/tags.yaml
```

### Policies

Right-sizing and tagging follow two YAML files. ProvisionGuard uses the first it finds:

1. the paths under `policies:` in `provisionguard.yaml`
2. `policy/rightsizing.yaml` and `policy/tagging.yaml` in your repository
3. the defaults in [`provisionguard/policies/`](provisionguard/policies/); copy them as a starting point

Right-sizing sets the largest allowed size per environment (taken from each resource's `environment` tag). Tagging lists the required tags and their allowed values.

### Terraform state

To see what already exists, the plan needs your Terraform state. With an S3 bucket (block public access on, versioning on), leave the bucket name out of the code:

```hcl
terraform {
  backend "s3" {
    key     = "infra/terraform.tfstate"
    encrypt = true
  }
}
```

and pass it in the workflow:

```yaml
          terraform-init-args: >-
            -backend-config=bucket=tfstate-{account_id}
            -backend-config=region=us-east-1
```

Without state, every resource looks new, and the existing-infrastructure section reports nothing affected.

## Versions

| You write | You get |
|---|---|
| `@v1` | The latest 1.x release; fixes arrive automatically |
| `@v1.0.0` | Exactly that release, until you change it |

Changes that could break existing workflows get a new major version (`v2`).

## Run it locally

```bash
pip install "git+https://github.com/SanthaprakashMahendran/provisionguard"
cd your-terraform
terraform init && terraform plan -out=tfplan && terraform show -json tfplan > plan.json
TF_DIR=. provisionguard --plan plan.json --dry-run
```

`--dry-run` prints the review instead of posting it, using your local AWS credentials.

## Safety

- Read-only: only describe, list and get calls to AWS; nothing is applied.
- No stored AWS keys: GitHub gets short-lived credentials for each run, and only for repositories your role trusts.
- Claude runs with all tools disabled, treats pull request content as data, and never decides the verdict.
- The raw scanner findings are always included, so nothing depends on the AI alone.

## Troubleshooting

| Problem | Fix |
|---|---|
| "Not authorized to perform sts:AssumeRoleWithWebIdentity" | The trust policy's `sub` doesn't match. Check the numeric IDs; if your repository's token has none, use `repo:<OWNER>/<REPO>:pull_request` |
| No comment on a pull request | It changed nothing under `terraform-dir`, `policy/` or `provisionguard.yaml`. Set `skip-unchanged: false` to review every pull request |
| "Nothing existing affected", although resources exist | The plan can't read your state; see [Terraform state](#terraform-state) |
| The role or bucket disappears | If your AWS account deletes untagged resources, add the tag it exempts to the identity provider, the role and the bucket |

## Development

```bash
pip install -e .
python -m unittest discover tests
```

The tests use sample plans and fake AWS responses, so they need no AWS account, Terraform or Claude. On GitHub, [`test.yml`](.github/workflows/test.yml) runs them on every pull request with Python 3.9 and 3.12. They cover the Python code; to try a change to `action.yml`, point a test repository at your branch (`uses: SanthaprakashMahendran/provisionguard@my-branch`).

To release, tag the merged commit and move the major tag:

```bash
git tag v1.0.1 && git tag -f v1
git push origin v1.0.1 && git push -f origin v1
```
