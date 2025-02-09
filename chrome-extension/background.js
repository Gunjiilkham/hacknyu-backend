class CodeScanner {
    constructor() {
        // Risk patterns for developer-specific concerns
        this.riskPatterns = {
            // Dangerous functions
            "eval(": { level: "CRITICAL", message: "⚠️ Dangerous: Dynamic code execution" },
            "Function(": { level: "CRITICAL", message: "⚠️ Dangerous: Dynamic code execution" },
            "document.write(": { level: "HIGH", message: "⚠️ Warning: DOM manipulation" },
            "innerHTML": { level: "MEDIUM", message: "⚠️ Warning: Potential XSS risk" },

            // Suspicious APIs
            "XMLHttpRequest": { level: "MEDIUM", message: "⚠️ Note: Network request detected" },
            "fetch(": { level: "MEDIUM", message: "⚠️ Note: Network request detected" },
            "WebSocket(": { level: "MEDIUM", message: "⚠️ Note: WebSocket connection detected" },

            // Hardcoded secrets
            "api_key": { level: "HIGH", message: "⚠️ Warning: API key detected" },
            "secret_key": { level: "HIGH", message: "⚠️ Warning: Secret key detected" },
            "password": { level: "HIGH", message: "⚠️ Warning: Password detected" },

            // Sketchy domains
            ".tk": { level: "HIGH", message: "⚠️ Warning: Suspicious TLD detected" },
            ".ml": { level: "HIGH", message: "⚠️ Warning: Suspicious TLD detected" },
            "free-download": { level: "HIGH", message: "⚠️ Warning: Sketchy download source" },
        };
    }

    async scanCode(code) {
        try {
            if (!code) {
                return {
                    isSuspicious: false,
                    riskLevel: "SAFE",
                    warnings: [],
                    details: { message: "✅ No code provided" }
                };
            }

            const alerts = [];
            let riskLevel = "SAFE";

            // Check for risky patterns
            for (const [pattern, details] of Object.entries(this.riskPatterns)) {
                if (code.includes(pattern)) {
                    alerts.push(details.message);
                    riskLevel = details.level;
                }
            }

            // Determine if suspicious
            const isSuspicious = alerts.length > 0;

            return {
                isSuspicious,
                riskLevel,
                warnings: alerts,
                details: {
                    message: "🔍 Scan complete",
                    codeLength: code.length,
                    foundRisks: alerts
                }
            };
        } catch (error) {
            return {
                isSuspicious: true,
                riskLevel: "CRITICAL",
                warnings: [`⚠️ Error: ${error.message}`],
                details: { message: "❌ An error occurred during scanning" }
            };
        }
    }

    async scanPageContent(content) {
        try {
            if (!content) {
                return {
                    isSuspicious: false,
                    riskLevel: "SAFE",
                    warnings: [],
                    details: { message: "✅ No content provided" }
                };
            }

            const alerts = [];
            let riskLevel = "SAFE";

            // Check for phishing indicators
            if (content.includes("password")) {
                alerts.push("⚠️ Warning: Password field detected");
                riskLevel = "HIGH";
            }
            if (content.includes("credit card")) {
                alerts.push("⚠️ Critical: Credit card field detected");
                riskLevel = "CRITICAL";
            }

            // Check for sketchy domains
            if (content.includes(".tk") || content.includes(".ml")) {
                alerts.push("⚠️ Warning: Suspicious TLD detected");
                riskLevel = "HIGH";
            }

            // Determine if suspicious
            const isSuspicious = alerts.length > 0;

            return {
                isSuspicious,
                riskLevel,
                warnings: alerts,
                details: {
                    message: "🔍 Scan complete",
                    contentLength: content.length,
                    foundRisks: alerts
                }
            };
        } catch (error) {
            return {
                isSuspicious: true,
                riskLevel: "CRITICAL",
                warnings: [`⚠️ Error: ${error.message}`],
                details: { message: "❌ An error occurred during scanning" }
            };
        }
    }
}

// Export for use in Chrome extension
const scanner = new CodeScanner();
export default scanner; 