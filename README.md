# Flexera One — Service Account Manager (GUI)

A single-file PowerShell + Windows Forms GUI for managing **Flexera One IAM service accounts** and their **API client credentials** through the Flexera One REST API — no browser required.

Create service accounts, assign and revoke roles, browse available roles, and manage each account's API clients (the `clientId`/`clientSecret` pairs used for `client_credentials` authentication) — all from one window.

![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-blue) ![Windows](https://img.shields.io/badge/OS-Windows-lightgrey)

---

## Capabilities

| Tab | What it does |
|-----|--------------|
| **Create Account** | Create a new service account and (optionally) assign one or more roles in a single step. |
| **Assign Roles** | Assign roles to an existing subject (service account or user) by subject ref + scope ref. |
| **View Assigned Roles** | Look up the roles granted to a subject ref, and **revoke** selected roles. |
| **Available Roles** | Browse every role in the org (name, display name, category, description). |
| **Manage Accounts** | List all service accounts, filter by name, see a **Credentials** column, **delete** accounts, and open **Manage Clients** for any account. Right-click to copy an account's ref/ID/name. |
| **Log** | Live, color-coded view of the session log with a "Refresh" and "Open Log Folder" button. |

### Service account client management
A service account can have **multiple clients**, each being one `clientId` / `clientSecret` pair. From **Manage Accounts → Manage Clients…** you can:

- **List** all clients of an account (clientId, created at, created by, kind — secrets are never shown after creation).
- **Create** a new client — the `clientId` and `clientSecret` are displayed in a **copy-once dialog** (Copy buttons + *Save to File*). The secret is shown **only once** and is never written to the log.
- **Delete** a client by `clientId`, with an explicit warning that any application using it will immediately stop working.

The **Credentials** column on the Manage Accounts tab shows each account's client status:

| Value | Meaning |
|-------|---------|
| `Yes (N)` | Account has N client(s). |
| `No` | Account has no clients yet. |
| `?` | Credential status could not be determined (clients endpoint unavailable — see Log). |

> **Credential rotation (no downtime):** create a new client, switch your application to it, confirm it works, then delete the old client.

---

## Requirements

- **Windows** with **Windows PowerShell 5.1** (uses `System.Windows.Forms` / `System.Drawing`).
- A Flexera One **Organization ID**.
- A Flexera One **user refresh token** with permission to manage IAM (e.g. `iam_admin` / Org Owner). Roles can only be loaded and assigned if your account has the necessary IAM permissions.
- Outbound HTTPS to the Flexera One API and login endpoints (TLS 1.2).

---

## Getting a refresh token

1. Sign in to Flexera One.
2. Go to the user menu → **Preferences** (or **Settings**) → **API Tokens** (a.k.a. *refresh tokens*).
3. Create a token and copy it. Refresh tokens are long-lived (they expire after one year of non-use) and inherit your user's permissions.

The tool exchanges this refresh token for a short-lived (1-hour) access token at connect time; the refresh token field is cleared from memory immediately after use.

---

## Usage

1. Download `New-FlexeraServiceAccount.ps1`.
2. Launch it (right-click → **Run with PowerShell**, or from a console):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\New-FlexeraServiceAccount.ps1
   ```
3. In the **Connection** bar at the top:
   - Enter your **Org ID**.
   - Select your **Region** (US / EU / AU).
   - Paste your **Refresh Token**.
   - Click **Connect**. On success the indicator turns green and the available roles load. The *Scope Ref* fields are auto-filled as `ref:nam:::iam:org:<OrgId>`.

### Create a service account with a credential
1. **Create Account** tab → enter a name (and optional description / roles) → **Create Account**.
2. Switch to **Manage Accounts** → **Load Accounts** → select the new account.
3. Click **Manage Clients…** → **Create New Client**.
4. Copy the `clientId` and `clientSecret` from the dialog (or *Save to File*). **The secret is shown only once.**

### Authenticate as the service account
Once you have a `clientId` / `clientSecret`, request an access token with the `client_credentials` grant:

```powershell
$tok = Invoke-RestMethod -Method Post -Uri 'https://login.flexera.com/oidc/token' `
    -ContentType 'application/x-www-form-urlencoded' `
    -Body @{ client_id = $clientId; client_secret = $clientSecret; grant_type = 'client_credentials' }
$headers = @{ Authorization = "Bearer $($tok.access_token)" }
```

The service account's permissions in the API are determined by the roles assigned to it.

---

## Regional endpoints

| Zone | API base | Token endpoint |
|------|----------|----------------|
| North America (US) | `api.flexera.com` | `login.flexera.com/oidc/token` |
| Europe (EU) | `api.flexera.eu` | `login.flexera.eu/oidc/token` |
| Asia-Pacific (AU) | `api.flexera.com.au` | `login.flexera.com.au/oidc/token` |

> The tool selects these automatically based on the **Region** dropdown.

---

## API endpoints used

| Operation | Method & path |
|-----------|---------------|
| Authenticate (user) | `POST {login}/oidc/token` (grant `refresh_token`) |
| Authenticate (service account) | `POST {login}/oidc/token` (grant `client_credentials`) |
| List roles | `GET /iam/v1/orgs/{orgId}/roles?view=extended` |
| Create service account | `POST /iam/v1/orgs/{orgId}/service-accounts` |
| List service accounts | `GET /iam/v1/orgs/{orgId}/service-accounts` |
| Delete service account | `DELETE /iam/v1/orgs/{orgId}/service-accounts/{id}` |
| List clients | `GET /iam/v1/orgs/{orgId}/service-accounts/{id}/clients` |
| Create client | `POST /iam/v1/orgs/{orgId}/service-accounts/{id}/clients` |
| Delete client | `DELETE /iam/v1/orgs/{orgId}/service-accounts/{id}/clients/{clientId}` |
| Grant role | `PUT /iam/v1/orgs/{orgId}/access-rules/grant` |
| Revoke role | `PUT /iam/v1/orgs/{orgId}/access-rules/revoke` |
| List access rules | `GET /iam/v1/orgs/{orgId}/access-rules?view=extended` |

Subject refs are converted from the API list format `iam#service-account:<id>` to the grant format `ref:nam:::iam:service-account:<id>` automatically.

---

## Logging

- A timestamped, color-coded log is written to `.\Logs\FlexeraSAM_YYYYMMDD.log` (next to the script).
- Every API call (method, URL, outcome) is logged. **Client secrets are never logged** — only the `clientId` is recorded on creation.
- View it live on the **Log** tab, or open the folder with **Open Log Folder**.

---

## Security notes

- The refresh token is cleared from the input field immediately after connecting, and tokens are dropped (and GC forced) when the form closes.
- `clientSecret` values are displayed once at creation and never persisted by the tool. If you use *Save to File*, store that file securely and delete it once the secret is in your secret manager.
- A lost or compromised client should be deleted immediately via **Manage Clients → Delete Selected**.

---

## Notes & compatibility

- The file is **pure ASCII** with no byte-order mark, so it loads correctly under PowerShell 5.1 regardless of how editors or sync clients re-encode it.
- Targets PowerShell 5.1; no PowerShell 7+ syntax is used.
- IPv4 / HTTPS only; TLS 1.2 is forced at startup.
