# FireConX — Mobile Firebase recon + API-key usability scanner

**FireConX** is a lightweight Bash tool to perform quick security checks against Firebase Realtime Database, Firebase Storage and Google Maps/Google APIs. It focuses on *unauthenticated/public exposure* checks (pentest mode) and will not attempt to log in to targets.

> ⚠️ **Important:** Run this tool only against targets you own or have explicit permission to test. Unauthorized scanning or write attempts can be illegal.

---

## Features

* Normalize and validate Firebase URLs (`https://...`) automatically
* Test common database paths (root, users, messages, orders)
* Test write permissions using safe PUT/POST probes (can be disabled)
* Test Firebase Storage bucket accessibility
* Test Google Maps API endpoints and inspect response body for API errors (e.g. `REQUEST_DENIED`)
* Check basic API key restrictions for several Google services
* Colorized terminal output + saved logfile and summary in output directory
* Saves problematic Google API responses to JSON files for later inspection

---

## Requirements

* `bash` (GNU bash)
* `curl` (with TLS support)
* Unix-like OS (Linux, macOS)

---

## Installation

No installation is required. Make the shipped script executable:

```bash
chmod +x fireconx.sh
```

Then run it as described below.

---

## Usage

```
./fireconx.sh --url <firebase_url> [--key <google_api_key>]
```

### Examples

* Basic Firebase-only scan (scheme optional):

```bash
./fireconx.sh --url your-project.firebaseio.com
```

* Firebase + Google API checks (supply API key):

```bash
./fireconx_v2.5.sh --url https://your-project.firebaseio.com --key AIzaSy...123
```

* Custom output folder:

```bash
./fireconx_v2.5.sh --url myproject.firebaseio.com --key AIza... --output results_2025
```

---

## What the script does (summary)

1. Normalize the given Firebase URL so it always uses `https://` and removes extra slashes.
2. Probe common Realtime Database paths with `GET` and evaluate responses:

   * Marks `SECURE` when HTTP returns `401/403` or the response body contains explicit permission/auth errors.
   * Marks `VULNERABLE` when a `2xx` response includes a non-empty non-null JSON body on `GET`.
3. Optionally attempts safe write probes (PUT/POST) to detect unauthenticated write permissions.
4. Probes Firebase Storage public endpoints.
5. Calls Google Maps endpoints and evaluates the JSON body for API errors (e.g. `REQUEST_DENIED`) even when HTTP `200`.
6. Checks simple API key restrictions by requesting a test path on several Google services.
7. Prints colorized output and writes `pentest.log` + `summary.txt` and any saved error JSONs into the output folder.

---

## Output

The script creates an output directory (default: `pentest_YYYYMMDD_HHMMSS`) containing:

* `pentest.log` — full colorized log (contains ANSI escapes). If you prefer a plain-log, strip ANSI sequences.
* `summary.txt` — brief summary of findings.
* `*_google_error.json` — saved Google API error responses (when applicable).

---

## Recommended safe options / tips

* If you want to avoid write probes, remove or comment the write test lines (`PUT`/`POST`) in the script or request a `--no-write` option if you implement it.
* Use a controlled environment (staging) or ask for explicit authorization before running against production.
* If a Google Maps endpoint returns HTTP `200` but `REQUEST_DENIED` in the JSON body, that means the endpoint requires a valid API key and therefore is not publicly usable — the script will mark it as secure and save the body for inspection.

---

## Troubleshooting

* `No HTTP response` or status `000` — network, DNS or `curl` timeout issues. You can increase the timeout in the script `do_curl()` function.
* `Unexpected status 000` for remote hosts — verify that the machine can resolve `maps.googleapis.com` and has outbound HTTPS access.
* Log file contains ANSI color codes — if you want a plain log, pipe the lines through `sed -r "s/\x1B\[[0-9;]*[A-Za-z]//g"`.

---

## Contributing

Pull requests are welcome. Things you could help with:

* Add `--no-write` and `--timeout/--retries` CLI flags
* Add an option to output log files without color codes
* Integrate with MobSF output to auto-populate targets

---

## License

MIT License — see LICENSE file if included.