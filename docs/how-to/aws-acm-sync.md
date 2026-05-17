# Sync certificates from AWS ACM

The AWS Certificate Manager (ACM) adapter ingests certificate metadata from
ACM into NetBox SSL as a read-only External Source. The adapter ships in
the optional `[aws]` extras — install it with:

```bash
pip install netbox-ssl[aws]
```

## Minimum IAM policy

The adapter needs three read-only ACM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "acm:GetCertificate"
      ],
      "Resource": "*"
    }
  ]
}
```

Attach this policy to the IAM user (for `aws_explicit` auth) or instance
role (for `aws_instance_role` auth) that NetBox uses.

## Authentication options

### Option A — Explicit credentials (`aws_explicit`)

For NetBox installations outside AWS or where you prefer rotating keys
yourself.

1. Create an IAM user with the policy above.
2. Generate an access key for the user.
3. Set environment variables in the NetBox process:

```bash
export NETBOX_AWS_ACCESS_KEY_ID="AKIA..."
export NETBOX_AWS_SECRET_ACCESS_KEY="..."
# Optional, for STS temporary credentials:
export NETBOX_AWS_SESSION_TOKEN="..."
```

4. In the External Source form (or via API), set:

```json
{
  "name": "AWS ACM (eu-west-1)",
  "source_type": "aws_acm",
  "region": "eu-west-1",
  "auth_method": "aws_explicit",
  "auth_credentials": {
    "access_key_id": "env:NETBOX_AWS_ACCESS_KEY_ID",
    "secret_access_key": "env:NETBOX_AWS_SECRET_ACCESS_KEY",
    "session_token": "env:NETBOX_AWS_SESSION_TOKEN"
  }
}
```

The `env:VAR_NAME` references are resolved at sync time — secrets are never
written to the NetBox database.

### Option B — Instance role (`aws_instance_role`)

For NetBox running on AWS infrastructure (EC2 with IAM role, ECS task with
task role, Lambda with execution role). Requires IMDSv2 enabled on EC2.

1. Attach an IAM role with the policy above to the NetBox compute resource.
2. In the External Source form, set:

```json
{
  "name": "AWS ACM (eu-west-1)",
  "source_type": "aws_acm",
  "region": "eu-west-1",
  "auth_method": "aws_instance_role",
  "auth_credentials": {}
}
```

The boto3 default credential chain discovers the instance role
automatically — no env vars needed.

## What gets imported

The adapter imports the following per certificate:

- `external_id` — full ACM ARN
- `common_name` — `DomainName`
- `sans` — `SubjectAlternativeNames`
- `valid_from` / `valid_to` — `NotBefore` / `NotAfter`
- `status` — mapped from ACM `Status` (see below)
- `issuer` — `Issuer`
- `serial_number` — `Serial`
- `algorithm` / `key_size` — parsed from `KeyAlgorithm`
- `pem_content` — public PEM from `GetCertificate`
- `issuer_chain` — chain PEM from `GetCertificate`
- `fingerprint_sha256` — computed from `pem_content`

### Status mapping

| ACM Status | NetBox SSL Status | Behaviour |
|---|---|---|
| `ISSUED` | `active` | Imported |
| `EXPIRED` | `expired` | Imported |
| `REVOKED` | `revoked` | Imported |
| `PENDING_VALIDATION` | `pending` | Imported |
| `FAILED` | — | **Skipped** (no usable cert) |
| `INACTIVE` | — | **Skipped** (disabled by AWS) |
| `VALIDATION_TIMED_OUT` | — | **Skipped** (no usable cert) |

Skipped certs are not visible in NetBox. To see them, check the AWS console.

## Multi-region setups

One External Source corresponds to one AWS region. For a multi-region ACM
footprint, create one External Source per region (e.g., one for `eu-west-1`,
one for `us-east-1`). Each runs its own sync schedule and IAM context.

## What is NOT supported

- ACM Private CA (`acm-pca`) — different service, separate adapter
- DNS validation record manipulation
- Cross-account `sts:AssumeRole` chains beyond direct credentials
- ACM write operations (request, renew, import, delete)
- `export-certificate` (passphrase-encrypted private keys) — never called

## Troubleshooting

### "Connection failed: AccessDeniedException"

The IAM user/role lacks one of the three required ACM permissions. Verify
the policy attached to the principal includes `acm:ListCertificates`,
`acm:DescribeCertificate`, and `acm:GetCertificate`.

### "Cannot reach ACM in region 'XXX'"

Either the region name is wrong, or NetBox cannot make outbound HTTPS
connections to `acm.<region>.amazonaws.com`. Check region spelling and
network egress rules.

### "No AWS credentials available"

You configured `aws_instance_role` but NetBox is not running on an AWS
compute resource with an IAM role. Either move to AWS (and attach a role)
or switch to `aws_explicit` with stored credentials.

### Sync completes but 0 certs found

Check the configured region — ACM is region-scoped. A cert in `us-east-1`
is invisible to a source configured for `eu-west-1`.
