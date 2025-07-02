# 🔐 Adobe Sign + OpenText xECM Integration

Automated digital signature workflow using Adobe Sign, fully integrated with OpenText Content Server (OTCS).

## 📌 Purpose

This project enables the sending of documents from OTCS to Adobe Sign for electronic signatures, automatic retrieval of the signed document, and final upload to the correct folder in the Content Server — all via API, with no manual intervention.

---

## 🧱 Architecture

- **Frontend (HTML + JS)**  
  Embedded page within OTCS via WebReport, used as the execution trigger.

- **Backend (Node.js + Express)**  
  Server responsible for:
  - OAuth2 authentication with Adobe Sign (via refresh token)
  - Document download via OTCS API (authenticated via OTDS)
  - Sending documents for signature
  - Asynchronous monitoring via Webhook
  - Automatic upload of the signed PDF to OTCS

---

## ⚙️ Features

- 🔁 Continuous integration with Adobe Sign using refresh token
- 📅 Secure download of the original PDF via OTCS API
- ✍️ Supports multiple signers (via Adobe Sign)
- 📡 Webhook to monitor signature status
- 📄 Automatic upload of the signed PDF to the designated folder in OTCS
- 🗒️ Detailed logging (`audit.log`, `error.log`, webhook payloads)
- 🧼 Optional purge of temporary files
- ⛔ Duplicate check: prevents resending the same document to the same recipients within 15 minutes

---

## 🚀 How to Run

### 1. Clone the repository

```bash
git clone https://github.com/Activos-Digitales-xECM-LATAM/adobe-api.git
cd project-name
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure `.env`

Create a `.env` file in the root folder with the following variables:

```env
# Adobe Sign
CLIENT_ID=your_client_id
CLIENT_SECRET=your_client_secret
NGROK_HOST=https://your-endpoint.ngrok.app (optional, you can use any HTTP tunnel or port-forwarded IP)

# OpenText
OTCS_BASE=https://your-content-server/api/v1
OTCS_USER=otds.username
OTCS_PASS=otds.password
```

### 4. Start the server

```bash
node backend.js
```

---

## 🔀 Webhook

- **Endpoint:** `/webhook`
- **Method:** `POST`
- **Content-Type:** `application/json`

Used to:

- Monitor signature events (e.g., `AGREEMENT_COMPLETED`)
- Download signed PDF
- Upload the document to OTCS

---

## 📁 Folder Structure

```
/
├── .env                  # Environment variables
├── .gitignore
├── package.json
├── package-lock.json
├── readme.md
├── tokens.json           # Stored tokens (avoid committing this)
│
├── node_modules/
│
└── server/
    ├── http/
    │   ├── ngrok.exe
    │   └── runngrok.bat
    │
    ├── inProcess/
    │   └── Document.pdf (temporary storage)
    │
    ├── logs/
    │   ├── audit.log
    │   ├── error.log
    │   └── webhook_raw.log
    │
    └── serverModules/
        ├── agreements.json
        ├── backend.js
        ├── logger.js
        ├── otcsManager.js
        └── tokenManager.js
```

---

## 🧠 Technical Insights

- Uses Adobe Sign OAuth 2.0 with refresh token to avoid frequent re-authentication.
- Replaces public URL method with OTDS authentication for secure, restricted environments.
- Temporarily stores files with optional weekly cleanup.
- All mapping and tracking logic is managed by `agreements.json`, storing recipients and creation dates to avoid duplicate sends.

---

## 🛡️ Security

- No sensitive tokens are exposed on the frontend.
- Passwords and keys are read from the `.env` file.
- Webhook filters out irrelevant events and only processes mapped agreements.

---

## 🧊 Testing

- Compatible with protected documents
- Supports multiple signers

---

## 🧙‍♂️ Developer

Pedro Barone

---

## 📄 License

This project is for internal use by Stratesys employees only.
