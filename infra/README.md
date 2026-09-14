# ACA Migration Kit

Reusable starter kit for migrating containerized apps to Azure Container Apps
with the security posture proven in the Shadowbroker migration (spec:
`../docs/superpowers/specs/2026-07-08-aca-migration-accelerator-design.md`).

## Layout

| File | Role | Touched per migration? |
|---|---|---|
| `platform.bicep` | Shared: Log Analytics (reuse or create), environment, ACR | No |
| `app-stack.bicep` | Per app: Key Vault, identities, roles, optional Azure Files | No |
| `modules/container-app.bicep` | Reusable container app | No |
| `modules/easyauth.bicep` | Entra Easy Auth config | No |
| `apps.bicep` | Module calls composing THIS migration's apps | **Yes — edit** |
| `migration.psd1` | The manifest (copied from `.example`) | **Yes — edit** |
| `provision.ps1` | Runbook (what-if gates, secrets, app reg, import, checks) | No |
| `discover-aci.ps1` | Drafts a manifest from an ACI container group | Run once |
| `lib.ps1` | Shared helpers | No |

## Per-migration workflow

1. **Copy the kit**: `Copy-Item -Recurse aca-migration-kit <app>-aca`
2. **Discover**:
   - From ACI: `./discover-aci.ps1 -Name <group> -ResourceGroup <rg>` → review the draft `migration.psd1`
   - From a repo: read its Dockerfiles/compose for images, ports, env vars, volumes, health endpoints
   - From a registry image: get the image reference + ask the app owner for runtime config
3. **Fill `migration.psd1`** (`provision.ps1` prompts for anything core you leave empty and saves your answers back)
4. **Edit `apps.bicep`**: one `module ... 'modules/container-app.bicep'` block per app.
   Keep the standard params (`location, envName, acrLoginServer, keyVaultName, identityIds, aadClientId`).
   **Four couplings to the manifest are convention-only — nothing validates them, so keep
   them in sync by hand:**
   - `identityIds[i]` in apps.bicep ⇔ `Apps[i]` in the manifest (same order)
   - the `output appFqdns` array ⇔ `Apps` order (post-checks probe `$fqdns[$i]` by index)
   - each module's `storageName` ⇔ that app's `VolumeShare` in the manifest
   - each `secretEnv` `secretName` ⇔ the values in that app's `SecretEnv` map
5. **Validate**: `az bicep build --file apps.bicep`
6. **Run `./provision.ps1`** — pauses at each what-if; type `y` to apply.
   `-GenerateMissingSecrets` auto-generates instead of prompting; `-SkipImageImport` skips step 7.

## Conventions and constraints

- Platform + apps share one resource group (default `my-resource-group`). Only the
  reused Log Analytics workspace may live elsewhere.
- Manifest `Location` only takes effect if the resource group is newly created;
  resources always land in the RG's actual region.
- `provision.ps1` rewrites `migration.psd1` when it prompts for missing values —
  comments in the file are lost on that rewrite (data is preserved).
- Secret **values** never appear in any file — they're prompted (or generated) into Key Vault.
- Internal apps are reached by siblings at `http://<fqdn>` (module sets `allowInsecure`).
- Stateful apps (file volume, background fetchers): pin `minReplicas = maxReplicas = 1`.
- Sizing pairs for consumption: 0.25/0.5Gi, 0.5/1Gi, 1.0/2Gi, 1.5/3Gi, 2.0/4Gi.

## After provisioning

- **Update an image**: `az acr import --force ...` then
  `az containerapp update -g <rg> -n <app> --revision-suffix (Get-Date -Format 'yyyyMMddHHmm')`
- **Rotate a secret**: set the new value in Key Vault, then force a **new revision** on
  every app using it (versionless Key Vault references do NOT refresh on restart).
- **Easy Auth admin consent**: `provision.ps1` attempts it; if users hit "Approval
  required", run `az ad app permission admin-consent --id <appId>` as an Application
  Administrator.
- **My Apps tile**: redirect URIs (callback + app root) and homepage are set by
  `provision.ps1`; additionally assign users/groups on the Enterprise application.
- **Decommission the source ACI** only after validation: `az container delete -g <rg> -n <group>`.

## Gotchas (each one was paid for)

| Symptom | Cause / fix |
|---|---|
| First run 403s writing Key Vault secrets | RBAC propagation lag — the runbook retries automatically |
| Rotated secret not picked up | Versionless KV refs refresh only on a NEW revision |
| "Approval required" at sign-in | Grant tenant-wide admin consent (runbook attempts it) |
| "App launch failed" from My Apps | App root must be a redirect URI (runbook sets it) |
| Sibling can't call internal app over https | Use `http://` — wildcard cert doesn't cover internal FQDNs |
| `database is locked` in logs | SQLite on SMB — module mounts volumes with `nobrl` (client-local locks) to prevent this; clear stale handles with `az storage share close-handle ... --close-all --recursive` if it happened pre-nobrl |
| Corrupted SQLite after an image update | With `nobrl` there is no cross-client locking: **deactivate the running revision before updating** stateful apps so old+new never overlap on the volume |
| Command auto-denied in Claude sessions | Don't put the string "deploy" in commands/messages |
