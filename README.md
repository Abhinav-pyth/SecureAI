# 🛡️ SecureAI: Web Application Security Testing Platform

An advanced, AI-powered web application security testing platform focusing on the OWASP Top 10 vulnerabilities.

![SecureAI Demo](./demo.webp)

## ✨ Advanced AI-Native Features

SecureAI goes beyond traditional regex-based DAST scanners by deeply integrating local Large Language Models (LLMs) like `llama3` to perform cognitive security analysis:

1. **Semantic Leak & Business Logic Detection**: 
   Instead of just scanning for regex patterns (like hardcoded AWS keys), SecureAI feeds the raw DOM and frontend JavaScript directly to the AI, asking it to detect structural or semantic leaks. It finds developer complaints (`FIXME: auth bypass`), internal network naming conventions, and client-side routing flaws.
2. **Zero-Day Payload Mutator (WAF Evasion)**: 
   If a traditional injection payload (SQLi, XSS) gets blocked by a Web Application Firewall (returning HTTP 403), the scanner prompts the AI to act as a red team operator, dynamically generating a highly obfuscated payload (e.g., using JSFuck, obscure SQL comments, or unicode tricks) on the fly to bypass the WAF.
3. **AI-Powered Vulnerability Auto-Patching**: 
   When vulnerabilities are found, the scanner automatically infers your underlying technology stack (e.g., Express, PHP, Nginx) from HTTP headers. It passes this to the AI during the reporting phase, generating exact, drop-in code snippets to fix out the vulnerabilities immediately.

## 🚀 Standard Features
- Full-stack Node.js + React architecture.
- JWT-based authentication with bcrypt hashing (login via Username or Email).
- Active HTTP probes for all 10 OWASP vulnerability categories.
- Beautiful dark glassmorphism UI with real-time scan progress polling.
- Automated, colour-coded PDF report generation using `pdfkit`.
- Completely local data persistence using `sql.js` (WebAssembly SQLite) – no complex database setups required.

## 📦 Requirements
- Node.js (v18+)
- [Ollama](https://ollama.com/) running locally (by default on `http://localhost:11434`)
- Required LLM pulled: `ollama pull llama3` (or set `OLLAMA_MODEL` in `.env` to Mistral etc.)

## 🛠️ Quick Start

### 1. Start the Backend API
The backend requires no compilation; it uses a WASM-based SQLite driver.
\`\`\`bash
cd backend
npm install
npm run dev
\`\`\`

### 2. Start the Frontend Application
\`\`\`bash
cd frontend
npm install
npm run dev
\`\`\`

### 3. Usage
1. Open your terminal and ensure `ollama serve` is running in the background.
2. Open `http://localhost:5173`.
3. Create an account, log in, and enter a test URL in the **New Scan** page.
4. Watch the progress bar fill as the 10 OWASP checks and 3 AI checks complete.
5. Review the AI-synthesized findings, WAF bypass attempts, and ✨ **AI Auto-Patch Code**.
6. Click **Download Report** to export to a formal PDF.

## 🏗️ Project Architecture
\`\`\`
d:/ai/
├── backend/          # Node.js + Express API
│   ├── src/
│   │   ├── db/       # sql.js WASM SQLite implementation
│   │   ├── models/   # User and Scan data access layers
│   │   ├── routes/   # Express routers
│   │   ├── services/ # scannerService (probes) & ollamaService (AI)
│   │   └── server.js # Entry point
│   ├── data/         # local SQLite persist file
│   └── package.json
└── frontend/         # React + Vite SPA
    ├── src/
    │   ├── pages/        # Dashboard, Login, Register, ScanDetail
    │   ├── components/   # UI elements
    │   ├── context/      # Auth state via JWT
    │   └── api/          # Axios interceptors for Auth
    └── package.json
\`\`\`

---
*Disclaimer: Only scan applications you own or have explicit written permission to test. This tool generates real attack payloads.*
