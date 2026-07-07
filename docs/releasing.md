# Cutting a release

Windows Guard auto-updates itself via GitHub Releases (Tauri's built-in
updater). To ship a new version:

1. Bump the version number in **three places** (they must match exactly):
   - `src-tauri/tauri.conf.json` → `"version"`
   - `package.json` → `"version"`
   - `src-tauri/Cargo.toml` → `version = "..."`
2. Commit the bump.
3. Tag it and push the tag:
   ```
   git tag v0.2.0
   git push origin v0.2.0
   ```
4. GitHub Actions (`.github/workflows/release.yml`) picks up the tag, builds
   the signed installer + MSI, and publishes a GitHub Release with the
   installer and a `latest.json` manifest attached.
5. Every running copy of Windows Guard checks that `latest.json` (via
   `plugins.updater.endpoints` in `tauri.conf.json`) on startup and every 4
   hours, silently downloads the update in the background, and shows a
   "Restart to update" button once it's ready.

## One-time setup (already done for this repo)

Four repository secrets make the CI build reproduce the same signing this
project uses locally:

| Secret | What it is |
|---|---|
| `WINDOWS_CERTIFICATE` | Base64 of the code-signing cert exported as a `.pfx` (with private key) |
| `WINDOWS_CERTIFICATE_PASSWORD` | Password protecting that `.pfx` |
| `TAURI_SIGNING_PRIVATE_KEY` | The Tauri updater's Ed25519 private key (from `tauri signer generate`) |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Password protecting that key |

None of this key material is committed to the repo — it lives only in
`%USERPROFILE%\.tauri\` locally and as encrypted GitHub Actions secrets.
If you ever need to rotate the updater key, generate a new one with
`npx tauri signer generate`, update `plugins.updater.pubkey` in
`tauri.conf.json`, and update the `TAURI_SIGNING_PRIVATE_KEY*` secrets —
but note that **older installs signed with the old key can no longer verify
new updates**, so this should only be done if the key is compromised.
