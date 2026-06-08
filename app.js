const form = document.querySelector("#url-form");
const input = document.querySelector("#url-input");
const sampleButtons = document.querySelectorAll("[data-sample]");
const statusPill = document.querySelector("#status-pill");
const scoreRing = document.querySelector("#score-ring");
const scoreValue = document.querySelector("#score-value");
const riskLabel = document.querySelector("#risk-label");
const riskSummary = document.querySelector("#risk-summary");
const findingsList = document.querySelector("#findings-list");
const breakdownList = document.querySelector("#breakdown-list");
const reportOutput = document.querySelector("#report-output");
const copyReport = document.querySelector("#copy-report");
const clearAnalysis = document.querySelector("#clear-analysis");
const historyList = document.querySelector("#history-list");

const suspiciousTlds = new Set(["zip", "mov", "top", "xyz", "click", "country", "ru", "cn", "tk", "gq"]);
const urlShorteners = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"]);
const suspiciousExtensions = new Set(["exe", "scr", "bat", "cmd", "js", "vbs", "zip", "rar", "iso"]);
const riskyKeywords = [
  "account",
  "billing",
  "confirm",
  "free",
  "gift",
  "login",
  "password",
  "secure",
  "signin",
  "update",
  "verify",
  "wallet"
];
const brandTargets = ["amazon", "apple", "bankofamerica", "chase", "facebook", "github", "google", "microsoft", "netflix", "paypal"];
const analysisHistory = [];

function normalizeUrl(rawUrl) {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    throw new Error("Enter a URL to analyze.");
  }

  try {
    return new URL(trimmed);
  } catch {
    return new URL(`https://${trimmed}`);
  }
}

function addFinding(findings, weight, severity, title, detail) {
  findings.push({ weight, severity, title, detail });
}

function getRegisteredDomain(hostname) {
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) {
    return hostname;
  }
  return parts.slice(-2).join(".");
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function analyzeUrl(rawUrl) {
  const parsed = normalizeUrl(rawUrl);
  const hostname = parsed.hostname.toLowerCase();
  const hostParts = hostname.split(".").filter(Boolean);
  const registeredDomain = getRegisteredDomain(hostname);
  const findings = [];
  const urlText = parsed.href.toLowerCase();
  const decodedPath = safeDecode(parsed.pathname).toLowerCase();

  if (parsed.protocol !== "https:") {
    addFinding(findings, 18, "High", "No HTTPS", "The URL does not use encrypted HTTPS transport.");
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    addFinding(findings, 22, "High", "IP address host", "Phishing campaigns often use raw IP addresses to avoid recognizable domains.");
  }

  if (hostname.includes("xn--")) {
    addFinding(findings, 20, "High", "Punycode domain", "The hostname uses encoded internationalized characters that can visually imitate trusted brands.");
  }

  if (hostParts.length >= 4) {
    addFinding(findings, 12, "Medium", "Deep subdomain chain", "The URL has multiple subdomains, which can hide the actual registered domain.");
  }

  const tld = hostParts.at(-1) || "";
  if (suspiciousTlds.has(tld)) {
    addFinding(findings, 12, "Medium", "Higher-risk TLD", `The .${tld} top-level domain is commonly seen in suspicious campaigns.`);
  }

  if (urlShorteners.has(registeredDomain)) {
    addFinding(findings, 14, "Medium", "URL shortener", "Shortened URLs hide the final destination until the link is expanded.");
  }

  if (parsed.href.length > 90) {
    addFinding(findings, 10, "Low", "Long URL", "Very long URLs can conceal redirects, tracking tokens, or deceptive paths.");
  }

  if (/%[0-9a-f]{2}/i.test(parsed.href)) {
    addFinding(findings, 10, "Medium", "Encoded characters", "The URL includes percent-encoded characters that can obscure the visible destination.");
  }

  if (parsed.port && !["80", "443"].includes(parsed.port)) {
    addFinding(findings, 9, "Low", "Unusual port", `The URL uses port ${parsed.port}, which is uncommon for normal web login pages.`);
  }

  if (parsed.href.includes("@")) {
    addFinding(findings, 18, "High", "At-symbol in URL", "The @ symbol can make the visible text before it look like the destination while the browser goes elsewhere.");
  }

  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    addFinding(findings, 8, "Low", "Many hyphens", "A high number of hyphens can indicate a generated or brand-spoofing domain.");
  }

  const extension = decodedPath.split(".").at(-1);
  if (extension && suspiciousExtensions.has(extension)) {
    addFinding(findings, 18, "High", "Suspicious file extension", `The path ends with .${extension}, which can be risky in phishing or malware delivery.`);
  }

  const longestSubdomain = hostParts.slice(0, -2).reduce((longest, part) => Math.max(longest, part.length), 0);
  if (longestSubdomain >= 24) {
    addFinding(findings, 8, "Low", "Long subdomain label", "A very long subdomain can be used to bury the meaningful destination.");
  }

  const keywordHits = riskyKeywords.filter((keyword) => urlText.includes(keyword));
  if (keywordHits.length >= 2) {
    addFinding(findings, 8 + keywordHits.length, "Medium", "Phishing-style keywords", `Found terms often used in credential theft lures: ${keywordHits.join(", ")}.`);
  }

  const brandHits = brandTargets.filter((brand) => urlText.includes(brand));
  const registeredDomainIncludesBrand = brandHits.some((brand) => registeredDomain.includes(brand));
  if (brandHits.length > 0 && !registeredDomainIncludesBrand) {
    addFinding(findings, 20, "High", "Brand impersonation signal", `Mentions ${brandHits.join(", ")} outside the registered domain.`);
  }

  if (hostname.includes("-") && brandHits.length > 0) {
    addFinding(findings, 8, "Low", "Hyphenated brand-like host", "Hyphenated hosts are often used to create fake brand-adjacent domains.");
  }

  const repeatedBrands = brandHits.filter((brand) => urlText.split(brand).length - 1 >= 2);
  if (repeatedBrands.length > 0) {
    addFinding(findings, 8, "Low", "Repeated brand term", `Repeated brand wording can be used to make a lure feel more legitimate: ${repeatedBrands.join(", ")}.`);
  }

  const score = Math.min(100, findings.reduce((total, finding) => total + finding.weight, 0));
  return { parsed, findings, score, registeredDomain };
}

function getRiskLevel(score) {
  if (score >= 70) return { label: "Critical risk", color: "#c43d32", status: "Critical" };
  if (score >= 45) return { label: "High risk", color: "#c43d32", status: "High" };
  if (score >= 25) return { label: "Moderate risk", color: "#bd7200", status: "Moderate" };
  return { label: "Low risk", color: "#1e8a5a", status: "Low" };
}

function renderBreakdown(parsed) {
  breakdownList.innerHTML = "";
  const values = [
    ["Protocol", parsed.protocol.replace(":", "") || "-"],
    ["Host", parsed.hostname || "-"],
    ["Path", parsed.pathname || "/"],
    ["Query", parsed.search || "-"]
  ];

  for (const [label, value] of values) {
    const row = document.createElement("div");
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = label;
    dd.textContent = value;
    row.append(dt, dd);
    breakdownList.append(row);
  }
}

function renderFindings(findings) {
  findingsList.innerHTML = "";

  if (findings.length === 0) {
    const item = document.createElement("li");
    item.className = "muted";
    item.textContent = "No major suspicious URL indicators were detected.";
    findingsList.append(item);
    return;
  }

  for (const finding of findings.sort((a, b) => b.weight - a.weight)) {
    const item = document.createElement("li");
    const severityClass = finding.severity.toLowerCase();
    const severity = document.createElement("span");
    const title = document.createElement("strong");

    severity.className = `severity severity-${severityClass}`;
    severity.textContent = finding.severity;
    title.textContent = finding.title;

    item.append(severity, title, `: ${finding.detail}`);
    findingsList.append(item);
  }
}

function buildReport(result, risk) {
  const timestamp = new Date().toLocaleString();
  const findingText = result.findings.length
    ? result.findings.map((finding) => `- [${finding.severity}] ${finding.title}: ${finding.detail}`).join("\n")
    : "- No major suspicious URL indicators were detected.";

  return `URL Risk Analysis Report

Analysis time: ${timestamp}
URL: ${result.parsed.href}
Registered domain: ${result.registeredDomain}
Risk rating: ${risk.label}
Score: ${result.score}/100

Summary:
The analyzed URL is rated ${risk.label.toLowerCase()} based on visible URL structure and known phishing indicators.

Findings:
${findingText}

Recommended analyst action:
${result.score >= 45 ? "Treat as suspicious, avoid opening in a normal browser session, and escalate for sandboxing or threat intelligence enrichment." : "No immediate high-risk URL indicators were found, but validate sender context and destination reputation before trusting it."}`;
}

function renderHistory() {
  historyList.innerHTML = "";

  if (analysisHistory.length === 0) {
    historyList.innerHTML = `<tr><td colspan="3" class="muted">No recent analyses yet.</td></tr>`;
    return;
  }

  for (const entry of analysisHistory) {
    const row = document.createElement("tr");
    const url = document.createElement("td");
    const score = document.createElement("td");
    const risk = document.createElement("td");

    url.textContent = entry.url;
    score.textContent = `${entry.score}/100`;
    risk.textContent = entry.risk;

    row.append(url, score, risk);
    historyList.append(row);
  }
}

function addToHistory(result, risk) {
  analysisHistory.unshift({
    url: result.parsed.href,
    score: result.score,
    risk: risk.label
  });
  analysisHistory.splice(5);
  renderHistory();
}

function renderResult(result) {
  const risk = getRiskLevel(result.score);
  const degrees = Math.round((result.score / 100) * 360);

  scoreValue.textContent = result.score;
  scoreRing.style.background = `conic-gradient(${risk.color} ${degrees}deg, #e6ece8 ${degrees}deg)`;
  riskLabel.textContent = risk.label;
  riskSummary.textContent = `The URL resolves to ${result.registeredDomain} and triggered ${result.findings.length} risk signal${result.findings.length === 1 ? "" : "s"}.`;
  statusPill.textContent = risk.status;
  statusPill.style.color = risk.color;
  renderFindings(result.findings);
  renderBreakdown(result.parsed);
  reportOutput.value = buildReport(result, risk);
  addToHistory(result, risk);
}

function renderError(error) {
  statusPill.textContent = "Error";
  statusPill.style.color = "#c43d32";
  riskLabel.textContent = "Unable to analyze";
  riskSummary.textContent = error.message;
}

function resetAnalysis() {
  input.value = "";
  scoreValue.textContent = "0";
  scoreRing.style.background = "conic-gradient(var(--green) 0deg, #e6ece8 0deg)";
  riskLabel.textContent = "No analysis yet";
  riskSummary.textContent = "Enter a URL to generate an analyst-style risk summary.";
  statusPill.textContent = "Ready";
  statusPill.style.color = "#1e8a5a";
  findingsList.innerHTML = `<li class="muted">No findings yet.</li>`;
  breakdownList.innerHTML = `
    <div><dt>Protocol</dt><dd>-</dd></div>
    <div><dt>Host</dt><dd>-</dd></div>
    <div><dt>Path</dt><dd>-</dd></div>
    <div><dt>Query</dt><dd>-</dd></div>
  `;
  reportOutput.value = "This report will populate after analysis.";
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  try {
    renderResult(analyzeUrl(input.value));
  } catch (error) {
    renderError(error);
  }
});

sampleButtons.forEach((button) => {
  button.addEventListener("click", () => {
    input.value = button.dataset.sample;
    renderResult(analyzeUrl(input.value));
  });
});

copyReport.addEventListener("click", async () => {
  await navigator.clipboard.writeText(reportOutput.value);
  copyReport.textContent = "Copied";
  setTimeout(() => {
    copyReport.textContent = "Copy report";
  }, 1200);
});

clearAnalysis.addEventListener("click", resetAnalysis);
