# SecureAI Web Vulnerability Scanner
An AI-powered web application security testing platform focusing on the OWASP Top 10 vulnerabilities.

## Features
- Full-stack Node.js + React architecture.
- JWT-based authentication with bcrypt hashing.
- Active HTTP probes for all 10 OWASP vulnerability categories.
- Integration with local Ollama LLMs (e.g. Llama 3) for vulnerability synthesis and risk scoring.
- Beautiful dark glassmorphism UI with real-time scan progress polling.
- Automated, colour-coded PDF report generation using PDFKit.

## Requirements
- Node.js (v18+)
- [Ollama](https://ollama.com/) running locally (by default on `http://localhost:11434`)
- Required LLM pulled: `ollama pull llama3` (or set `OLLAMA_MODEL` in `.env` to Mistral etc.)

## Quick Start

### 1. Start the Backend API
```bash
cd backend
npm install
npm run dev
```

### 2. Start the Frontend Application
```bash
cd frontend
npm install
npm run dev
```

### 3. Usage
1. Make sure Ollama is running in the background.
2. Open `http://localhost:5173`.
3. Create an account, log in, and enter a test URL in the New Scan page.
4. Watch the progress bar fill as the 10 OWASP checks complete.
5. Review the AI-synthesized findings, CVSS scores, and remediation priorities.
6. Click **Download Report** to export to PDF.
