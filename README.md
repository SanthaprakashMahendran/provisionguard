# ProvisionGuard

A GitHub Action that reviews Terraform pull requests **before anyone approves them**. It runs `terraform plan`, checks the result, and posts one comment on the PR that answers "is this safe to merge?":

- **Verdict**: a red, yellow or green box decided by fixed rules, plus a one-line scorecard per check
- 🔒 **Security**: findings from Checkov, Trivy and/or KICS, ranked and explained in plain English by Claude (optional)
- 💥 **Existing infrastructure**: names already taken in AWS, and changes that would delete or replace existing resources, with what depends on them
- 📊 **Service quotas**: current account usage plus this change against AWS limits
- 📏 **Right-sizing**: resources larger than their environment allows, with the monthly saving
- 🏷️ **Tagging**: missing or invalid required tags, with suggested values
- 💰 **Cost**: estimated monthly cost per resource from AWS list prices
- 🗺️ **Architecture**: a diagram of the change (needs Claude)

Every push to the PR updates the same comment. The action only **reads** from AWS: it never runs `terraform apply`.

## Quick start

**1. Let GitHub Actions log in to AWS (once per AWS account).** In IAM, add the identity provider `token.actions.githubusercontent.com` (audience `sts.amazonaws.com`) if it doesn't exist yet, then create a role with `ReadOnlyAccess` and this trust policy:

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

GitHub puts numeric IDs into `sub`. Find them with `GET https://api.github.com/repos/<OWNER>/<REPO>` (`owner.id` and `id`).

**2. Add repository secrets:** `AWS_ROLE_ARN` (the role's ARN) and, optionally, `CLAUDE_CODE_OAUTH_TOKEN` (run `claude setup-token` with a Claude Pro or Max account) for the AI assessment and the diagram.

**3. Add the workflow** to the repository that holds your Terraform, as `.github/workflows/terraform-review.yml`:

```yaml
name: Terraform review
on: pull_request

permissions:
  contents: read
  pull-requests: write
  id-token: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: SanthaprakashMahendran/provisionguard@v1
        with:
          terraform-dir: infra
          aws-role-arn: ${{ secrets.AWS_ROLE_ARN }}
          claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
```

Open a pull request that changes the Terraform, and the review appears as a comment.

The workflow runs on every pull request, and ProvisionGuard decides itself whether there's anything to review: if a PR changes nothing under `terraform-dir`, `policy/` or `provisionguard.yaml`, it stops within seconds without a plan or a comment. (A workflow's `paths:` filter can't use inputs, which is why the check lives in the action.)

## Inputs

| Input | Default | Purpose |
|---|---|---|
| `terraform-dir` | `infra` | Folder with the Terraform code |
| `aws-role-arn` | | Role to assume through OIDC. Leave empty if an earlier step already set up AWS credentials |
| `aws-region` | `us-east-1` | Region for AWS calls when the code doesn't set `aws_region` |
| `terraform-version` | `1.9.8` | Terraform version for the plan |
| `terraform-init-args` | | Extra `terraform init` arguments, e.g. backend settings. `{account_id}` is replaced with the AWS account ID |
| `terraform-plan-args` | | Extra `terraform plan` arguments, e.g. `-var-file=accounts/prod.tfvars` |
| `scanners` | | `checkov`, `trivy`, `kics`, comma-separated. Overrides `provisionguard.yaml` |
| `config` | `provisionguard.yaml` | Path to the settings file |
| `claude-code-oauth-token` | | Enables the AI assessment and the diagram |
| `github-token` | `github.token` | Token used to post the comment |
| `skip-unchanged` | `true` | Skip PRs that change nothing under `terraform-dir`, `policy/` or the settings file. `false` reviews every PR |
| `fail-on` | `never` | Fail the check on `caution` (red) or `warning` (yellow and red). With branch protection, this blocks merging |

**Outputs:** `verdict` is `caution`, `warning` or `ok` (empty when skipped); `reviewed` is `true` or `false`.

## Settings file

`provisionguard.yaml` in the repository root is optional:

```yaml
security:
  scanners: [checkov, trivy]        # any of: checkov, trivy, kics (default: checkov)

policies:                           # optional; see "Policies"
  rightsizing: rules/sizes.yaml
  tagging: rules/tags.yaml
```

| Scanner | How the action installs it | Notes |
|---|---|---|
| Checkov | Python package, isolated environment | Default |
| Trivy | Release download, checksum verified | Gives its own severities |
| KICS | Docker image `checkmarx/kics` | Gives its own severities; slowest to start |

## Policies

Right-sizing and tagging follow two YAML policies. ProvisionGuard looks for your own versions in this order, and otherwise uses its defaults:

1. the paths under `policies:` in `provisionguard.yaml`
2. `policy/rightsizing.yaml` and `policy/tagging.yaml` in your repository
3. the defaults in [`provisionguard/policies/`](provisionguard/policies/)

Copy a default as a starting point. Right-sizing caps each environment's size (from the `environment` tag); tagging lists required tags and allowed values.

## Existing-infrastructure checks

Name clashes work in any repository. Destructive changes need Terraform state the plan can read, e.g. an S3 backend:

```yaml
          terraform-init-args: >-
            -backend-config=bucket=tfstate-{account_id}
            -backend-config=region=us-east-1
```

Without state, every resource looks new and this section reports "nothing existing affected".

## Run it locally

```bash
pip install "git+https://github.com/SanthaprakashMahendran/provisionguard"
cd your-terraform && terraform init && terraform plan -out=tfplan && terraform show -json tfplan > plan.json
TF_DIR=. provisionguard --plan plan.json --dry-run
```

`--dry-run` prints the review instead of posting it. Checks that need AWS use your local AWS credentials.

## Safety

- Read-only: AWS calls are describe, list and get calls; the action never applies changes.
- Short-lived credentials through OIDC; no stored AWS keys.
- Claude runs with every tool disabled, treats the pull request's content as data, and never decides the verdict.
- Raw scanner findings are always included, so nothing depends on the AI alone.

## Development

```bash
pip install -e .
python -m unittest discover tests
```
