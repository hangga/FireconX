# 🔥 FireconX — How to Use

**FireconX** is an all-in-one mobile pentest helper.
It checks Firebase security rules and Google API key restrictions for Android/iOS apps.

> **Note:** You can often discover a project's Firebase Realtime Database URL and Google API key by analyzing the app (APK / IPA) with **Mobile Security Framework (MobSF)**. Use MobSF static analysis to inspect hardcoded strings, configuration files, and reconnaissance sections — it can quickly point you to Firebase endpoints and API keys to test with FireconX.

![firebase url](https://github.com/hangga/FireconX/blob/main/firebase_analysis.png?raw=true)
![google api](https://github.com/hangga/FireconX/blob/main/google_api_key.png?raw=true)

---

## 🧩 Requirements

* Linux or macOS terminal with **bash**
* **curl** installed
* You must have:

  * A **Firebase Realtime Database URL**, e.g. `https://myapp.firebaseio.com`
  * A **Google API key**, e.g. `AIzaSyABC123def456`
* **Authorization** to test the target (never test without permission)

---

## 🚀 Quick Examples

Basic usage:

```bash
./fireconx.sh https://myapp.firebaseio.com AIzaSyABC123def456
```

With options:

```bash
./fireconx.sh --url https://myapp.firebaseio.com --key AIzaSyABC123def456
```

Save logs to custom folder:

```bash
./fireconx.sh --url https://myapp.firebaseio.com --key AIzaSyABC123def456 --output my_pentest
```

Fast mode (skip slower tests):

```bash
./fireconx.sh --url https://myapp.firebaseio.com --key AIzaSyABC123def456 --fast
```

Quiet mode (minimal output):

```bash
./fireconx.sh --url https://myapp.firebaseio.com --key AIzaSyABC123def456 --quiet
```

Show help:

```bash
./fireconx.sh --help
```

---

## 🧠 What FireconX Does

* Checks **Firebase database** read/write access
* Tests **Google APIs** (Maps, Places, Directions, Translate, Vision, etc.)
* Tests **Firebase services** (Firestore, Auth, FCM)
* Checks **Firebase Storage** public access
* Detects if the **API key is restricted or open**

---

## 📂 Output Files

FireconX automatically creates a folder like:

```
firereconx_log_YYYYMMDD_HHMMSS
```

Inside you’ll find:

* `pentest.log` → full details of each test
* `summary.txt` → short summary + findings + recommendations

---

## 🕵️ Reading Results

Look for:

* `VULN` or `DATA EXPOSURE` → something exposed
* `API Key might be usable with:` → key is open
* `SUCCESS: ... Access denied` → secure

---

## ⚙️ Options

| Option     | Description            |
| ---------- | ---------------------- |
| `--url`    | Firebase database URL  |
| `--key`    | Google API key         |
| `--output` | Custom output folder   |
| `--fast`   | Skip some tests        |
| `--quiet`  | Minimal console output |
| `--help`   | Show help              |

---

## 🧩 Troubleshooting

If you get:

* **Permission denied:**
  → Run `chmod +x fireconx.sh`
* **curl: command not found:**
  → Install curl with `apt`, `yum`, or `brew`
* **No HTTP status:**
  → Check network and URL format

---

## ⚠️ Legal Reminder

Use FireconX **only** for apps or systems you own or have permission to test.
Unauthorized testing may be illegal.

---

## ✅ Short example workflow

1. Ensure you have permission.
2. Make the script executable:

   ```bash
   chmod +x fireconx.sh
   ```
3. Run:

   ```bash
   ./fireconx.sh --url https://myapp.firebaseio.com --key YOUR_API_KEY
   ```
4. Open the generated folder and read `summary.txt` and `pentest.log`.
5. Report findings and recommended fixes (Firebase Rules, API key restrictions, App Check, auth).

---

# How results are interpreted — Google API response patterns

When FireconX tests Google APIs it looks at two things: the **HTTP status code** and the **response body**. Below are common patterns you may see and what they usually mean:

* **HTTP 200 (OK) with useful JSON** — The API accepted the request and returned real data. If this happens using your API key it means the key is **usable** for that service (possible risk if key should be restricted).
* **HTTP 200 with an "error" field in JSON** — The endpoint responded but the body contains an error message (e.g., quota exceeded, invalid parameter). We treat this as **not vulnerable** because the call did not return successful data.
* **HTTP 401 / 403 (Unauthorized / Forbidden)** — The API key is **restricted** or invalid for that service. This is usually good (expected for properly-restricted keys).
* **HTTP 404 (Not Found)** — The endpoint or resource does not exist (not a vulnerability by itself).
* **HTTP 429 (Too Many Requests)** — The request was rate-limited. Not a vulnerability, but indicates the service enforces limits.
* **Other 4xx / 5xx** — Client or server errors. These are treated as **not vulnerable** for data exposure, but may indicate misconfiguration or instability.
* **Unexpected success on write endpoints (2xx on POST/PUT/PATCH/DELETE)** — Treated as **VULNERABLE**: the key or endpoint allowed changes. These are high-risk and need immediate attention.

**Tip:** FireconX logs the HTTP status and a short sample of the response body (first 500 bytes) so you can quickly verify whether a successful response actually returned sensitive data or just an error message.
