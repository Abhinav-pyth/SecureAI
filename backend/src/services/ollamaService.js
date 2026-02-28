const axios = require('axios');

const OLLAMA_BASE_URL = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'llama3';

const SYSTEM_PROMPT = `You are a senior cybersecurity expert and penetration tester specializing in OWASP Top 10 vulnerabilities. 
Analyze the provided security scan data and return a structured JSON response.
Always respond with valid JSON only, no markdown, no explanation outside of JSON.
Your response must follow this exact schema:
{
  "overallRiskScore": <number 0-100>,
  "riskLevel": "<Critical|High|Medium|Low|Informational>",
  "executiveSummary": "<2-3 sentence summary>",
  "keyFindings": ["<finding1>", "<finding2>", ...],
  "prioritizedRemediation": ["<action1>", "<action2>", ...],
  "findings": [
    {
      "owaspId": "<e.g. A01:2021>",
      "category": "<category name>",
      "severity": "<Critical|High|Medium|Low|Informational>",
      "description": "<what was found>",
      "evidence": "<specific evidence from scan>",
      "recommendation": "<specific fix>",
      "cvssScore": <number 0-10>
    }
  ]
}`;

/**
 * Sends a prompt to the Ollama API and returns the raw response.
 * @param {string} prompt The prompt to send to Ollama.
 * @returns {string} The raw text response from Ollama.
 */
async function generateAiResponse(prompt) {
    try {
        const response = await axios.post(
            `${OLLAMA_BASE_URL}/api/generate`,
            {
                model: OLLAMA_MODEL,
                prompt: prompt,
                // The system prompt is now integrated into the main prompt for better control
                // system: SYSTEM_PROMPT, // Removed as it's part of the new prompt structure
                stream: false,
                options: {
                    temperature: 0.1,
                    top_p: 0.9,
                    num_predict: 4096,
                },
            },
            { timeout: 120000 }
        );
        return response.data.response || '';
    } catch (err) {
        console.error('Error communicating with Ollama:', err.message);
        throw new Error(`Ollama API call failed: ${err.message}`);
    }
}

/**
 * Analyzes raw scanner findings and synthesizes a full report with code patches.
 * @param {Array} rawFindings Output from scannerService
 * @param {Array} techStack Inferred technology stack (e.g. ['Node.js', 'Express'])
 * @returns {Object} Structured JSON analysis
 */
async function analyzeScanResults(rawFindings, techStack = ['Generic Web App']) {
    if (!rawFindings || rawFindings.length === 0) return null;

    const prompt = `
You are an elite Application Security Engineer and AI Auto-Patcher.
Analyze the following raw security test findings.
The target application is built using this tech stack: ${techStack.join(', ')}.

Your task is to:
1. Summarize the vulnerabilities.
2. Calculate a realistic overall risk score (0-100) and risk level (Low/Medium/High/Critical).
3. Provide prioritized remediation steps.
4. NEW: For every vulnerability found (that requires a code fix), provide an "autoPatch" code snippet. Write the exact drop-in code (in the appropriate language for the tech stack) to fix the issue.

RESPOND ONLY WITH VALID JSON matching this exact structure:
{
  "executiveSummary": "1-2 sentences summarizing the security posture.",
  "overallRiskScore": 85,
  "riskLevel": "High",
  "keyFindings": ["Brief bullet 1", "Brief bullet 2"],
  "prioritizedRemediation": ["Step 1", "Step 2"],
  "findings": [
    {
      "owaspId": "A01:2021",
      "category": "Broken Access Control",
      "severity": "High",
      "cvssScore": 7.5,
      "description": "Details...",
      "evidence": "What was found...",
      "recommendation": "How to fix it globally...",
      "autoPatch": "const express = require('express');\\n// The actual code to fix it based on the tech stack..."
    }
  ]
}

Raw Findings to Analyze:
${JSON.stringify(rawFindings, null, 2)}
`;

    try {
        const rawResponse = await generateAiResponse(prompt);
        // Find the JSON block 
        const jsonMatch = rawResponse.match(/\{[\s\S]*\}/);
        if (!jsonMatch) throw new Error('AI did not return valid JSON');
        return JSON.parse(jsonMatch[0]);
    } catch (error) {
        console.error('Failed to parse AI response:', error.message);
        // Fallback if AI fails parsing
        return {
            executiveSummary: 'AI analysis failed. Raw results provided.',
            overallRiskScore: 0,
            riskLevel: 'Unknown',
            keyFindings: [],
            prioritizedRemediation: [],
            findings: rawFindings.filter(f => f.vulnerable).map(f => ({
                owaspId: f.owaspId,
                category: f.name,
                severity: f.severity,
                cvssScore: 5.0,
                description: f.description,
                evidence: f.evidence,
                recommendation: f.recommendation,
                autoPatch: 'AI auto-patching unavailable.'
            }))
        };
    }
}

module.exports = { analyzeScanResults, generateAiResponse };
