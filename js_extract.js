const puppeteer = require("puppeteer");
const puppeteerExtra = require("puppeteer-extra");
const StealthPlugin = require("puppeteer-extra-plugin-stealth");
puppeteerExtra.use(StealthPlugin());
const fetch = require("node-fetch");
const fs = require("fs").promises;
const path = require("path");
const dns = require("dns").promises;
const AbortController = require("abort-controller");

// Validate required dependencies
const checkDependencies = () => {
  const required = [
    "puppeteer",
    "puppeteer-extra",
    "puppeteer-extra-plugin-stealth",
    "node-fetch",
    "abort-controller",
  ];
  required.forEach((dep) => {
    try {
      require(dep);
    } catch (e) {
      console.error(
        `[!] Missing dependency: ${dep}. Please install with 'npm install ${dep}'`
      );
      process.exit(1);
    }
  });
};
checkDependencies();

// Command-line arguments with validation
const url = process.argv[2];
const outputDir = process.argv[3];
const mode = process.argv[4] || "enumerate";
const jsLinks =
  mode === "regex"
    ? process.argv[5]
      ? process.argv[5].split(",").filter((link) => link.trim())
      : []
    : [];
const headers = JSON.parse(
  process.argv[6] ||
    '[{"Accept":"text/html","User-Agent":"Mozilla/5.0","CF-Clearance":""}]'
);
const userAgents = JSON.parse(process.argv[7] || "[]");
const crawlDepth = parseInt(process.argv[8] || "10", 10);
const threads = parseInt(process.argv[9] || "10", 10);
const delay = parseInt(process.argv[10] || "5", 10);
const loginCreds = JSON.parse(process.argv[11] || "{}");
const selections = JSON.parse(process.argv[12] || "[]");
// Entropy threshold configurable via CLI or ENV
const entropyThreshold =
  typeof process.argv[13] !== "undefined"
    ? parseFloat(process.argv[13])
    : process.env.ENTROPY_THRESHOLD
    ? parseFloat(process.env.ENTROPY_THRESHOLD)
    : 0.8;

// Input validation
if (!url || !outputDir) {
  console.error("[!] Missing required arguments: URL or outputDir");
  process.exit(1);
}
if (
  ![
    "enumerate",
    "regex",
    "reflection",
    "sinks",
    "vulnerable",
    "sanitization",
    "characters",
  ].includes(mode)
) {
  console.error(
    `[!] Invalid mode: ${mode}. Valid modes: enumerate, regex, reflection, sinks, vulnerable, sanitization, characters`
  );
  process.exit(1);
}
if (mode === "regex" && jsLinks.length === 0) {
  console.error("[!] Regex mode requires jsLinks");
  process.exit(1);
}

// Error logging with context
const logError = async (msg, context = {}) => {
  const errorMsg = `[${new Date().toISOString()}] ${msg} | Context: ${JSON.stringify(
    context
  )}`;
  console.error(`[!] ${errorMsg}`);
  try {
    await fs.appendFile(
      path.join(outputDir, "error.log"),
      `${errorMsg}\n`,
      "utf8"
    );
  } catch (e) {
    console.error(`[!] Failed to log error: ${e.message}`);
  }
};

// Regex patterns for sensitive data
const sensitivePatterns = [
  {
    type: "admin_endpoint",
    regex: /\/admin(?:\/|$)[^\s"']*/gi,
    description: "Admin endpoint URLs (e.g., /admin/, /admin/dashboard)",
    validate: (match) => !/\/admin[\/\s]*(test|demo)/i.test(match),
  },
  {
    type: "alibaba_access_key_id",
    regex: /LTAI[0-9A-Za-z]{20}(?=\s*[:=]\s*["']?[0-9A-Za-z]{30,50}["']?)/gi,
    description: "Alibaba Cloud Access Key ID (20 chars, paired with secret)",
    validate: (match) => match.length === 24,
  },
  {
    type: "alibaba_access_key_secret",
    regex: /LTAI[0-9A-Za-z]{20,40}[0-9A-Za-z]{30,50}/gi,
    description: "Alibaba Cloud Access Key Secret (50-90 chars)",
    validate: (match) => match.length >= 50 && match.length <= 90,
  },
  {
    type: "analytics_tracking_id",
    regex: /UA-\d{4,9}-\d{1,4}/gi,
    description: "Google Analytics Tracking ID (UA-XXXX-Y)",
    validate: (match) => !/UA-0000-0/.test(match),
  },
  {
    type: "api_key",
    regex: /["']([a-zA-Z0-9_-]{20,64})["']/g,
    description: "API keys or tokens (20-64 chars, quoted)",
    validate: (match) => {
      const blacklist = [
        "drupal-settings-json",
        "additionalConfigInfo",
        "suppressDeprecationErrors",
        "dialog-off-canvas-main-canvas",
        "block-hackerone-partneronetapannouncement",
        "block-hackerone-useraccountmenu-menu",
        "block-hackerone-useraccountmenu",
        "block-hackerone-sitebranding",
        "block-hackerone-main-menu-menu",
        "block-hackerone-main-menu",
        "secondary-notice-bar",
        "menu-block-reference",
        "block-hackerone-mainnavigation-menu",
        "block-hackerone-mainnavigation",
        "block-hackerone-content",
        "social-proof-case-study-cards",
        "product-layout-items",
        "image-style-thumbnail",
        "block-hackerone-footerblock",
      ];
      if (blacklist.includes(match)) return false;
      if (/^(0+|1+)$/.test(match)) return false;
      if (/^[-_a-z]+$/i.test(match)) return false;
      if (/(block|menu|canvas|footer|header)/i.test(match)) return false;
      return true;
    },
  },
  {
    type: "aws_access_key_id",
    regex: /(?:AKIA|ASIA)[0-9A-Z]{16}/gi,
    description: "AWS Access Key ID (AKIA/ASIA + 16 chars)",
    validate: (match) => match.length === 20,
  },
  {
    type: "aws_account_id",
    regex: /\b\d{12}\b/g,
    description: "AWS Account ID (12 digits)",
    validate: (match) => match !== "000000000000" && match !== "000000000123",
  },
  {
    type: "aws_arn",
    regex: /arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s"']+/gi,
    description: "AWS ARN (includes service, region, account ID)",
  },
  {
    type: "aws_cloudfront_url",
    regex: /[a-z0-9]+\.cloudfront\.net/gi,
    description: "AWS CloudFront URL (subdomain.cloudfront.net)",
  },
  {
    type: "aws_dynamodb_url",
    regex: /dynamodb\.[a-z0-9\-]+\.amazonaws\.com/gi,
    description: "AWS DynamoDB endpoint",
  },
  {
    type: "aws_lambda_arn",
    regex: /arn:aws:lambda:[a-z0-9\-]+:\d{12}:function:[a-zA-Z0-9\-_]+/gi,
    description: "AWS Lambda ARN",
  },
  {
    type: "aws_rds_endpoint",
    regex: /[a-z0-9\-]+\.rds\.[a-z0-9\-]+\.amazonaws\.com/gi,
    description: "AWS RDS endpoint",
  },
  {
    type: "aws_secret_access_key",
    regex: /(?:AKIA|ASIA)[0-9A-Z]{16}\/[0-9A-Za-z+\/=]{40}/gi,
    description: "AWS Secret Access Key (40 chars after key ID)",
  },
  {
    type: "aws_secretsmanager_arn",
    regex: /arn:aws:secretsmanager:[a-z0-9\-]+:\d{12}:secret:[a-zA-Z0-9\-_]+/gi,
    description: "AWS Secrets Manager ARN",
  },
  {
    type: "aws_session_token",
    regex: /FQoGZXIvYXdzE[a-zA-Z0-9\/\+]{100,}/gi,
    description: "AWS Session Token (100+ chars)",
  },
  {
    type: "backup_file",
    regex: /\b[a-zA-Z0-9_-]+\.(bak|backup|old|tmp|swp|orig|save|copy)\b/gi,
    description: "Backup or temporary files",
  },
  {
    type: "base64_encoded_secret",
    regex:
      /(?:key|secret|token|password)\s*[:=]\s*["']([A-Za-z0-9+\/]{40,}(?:==|=)?)["']/gi,
    description: "Base64-encoded secret (40+ chars, quoted)",
  },
  {
    type: "basic_auth_in_url",
    regex: /https?:\/\/[^\/\s:@]+:[^\/\s:@]+@[^\/\s:]+/gi,
    description: "Basic auth credentials in URL (user:pass@host)",
  },
  {
    type: "bcrypt_hash",
    regex: /\$2[aby]\$[0-9]{2}\$[A-Za-z0-9\.\/]{53}/gi,
    description: "Bcrypt password hash ($2a/b/y$XX$53chars)",
  },
  {
    type: "client_id",
    regex: /client[_-]?id\s*[:=]\s*["']([a-zA-Z0-9\-_]{16,64})["']/gi,
    description: "OAuth Client ID (16-64 chars, quoted)",
  },
  {
    type: "client_secret",
    regex: /client[_-]?secret\s*[:=]\s*["']([a-zA-Z0-9\-_]{16,64})["']/gi,
    description: "OAuth Client Secret (16-64 chars, quoted)",
  },
  {
    type: "cloudinary_url",
    regex: /cloudinary:\/\/[0-9]{15}:[A-Za-z0-9_\-]+@[a-z0-9]+/gi,
    description: "Cloudinary API URL (api_key:secret@host)",
  },
  {
    type: "config_object",
    regex:
      /const\s+[a-zA-Z0-9_]+\s*=\s*\{[^}]*apiKey\s*:\s*["'][a-zA-Z0-9\-_]{16,64}["'][^}]*\}/gi,
    description: "JavaScript config object with apiKey",
  },
  {
    type: "cookie_flag",
    regex: /Set-Cookie:\s*[^;]+;[^"]*/gi,
    description: "Set-Cookie header",
  },
  {
    type: "cors_wildcard",
    regex: /Access-Control-Allow-Origin:\s*\*/gi,
    description: "CORS wildcard (*)",
  },
  // Additional patterns (abridged for brevity, all original patterns retained with similar validation)
  {
    type: "credit_card",
    regex:
      /(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})/g,
    description: "Credit card number (Visa, MC, Amex, Discover)",
    validate: (match) => {
      let sum = 0;
      let isEven = false;
      for (let i = match.length - 1; i >= 0; i--) {
        let n = parseInt(match[i], 10);
        if (isEven) {
          n *= 2;
          if (n > 9) n -= 9;
        }
        sum += n;
        isEven = !isEven;
      }
      const testNumbers = [
        "4111111111111111",
        "4012888888881881",
        "4222222222222",
        "5555555555554444",
        "378282246310005",
      ];
      return sum % 10 === 0 && !testNumbers.includes(match);
    },
  },
  {
    type: "csrf_token",
    regex:
      /(?:csrf_token|xsrf_token)\s*[:=]\s*["']([a-zA-Z0-9\-_]{16,64})["']/gi,
    description: "CSRF/XSRF token (16-64 chars, quoted)",
  },
  {
    type: "cvv",
    regex: /(?:cvv|cvc|cid)\s*[:=]\s*["']?(\d{3,4})["']?/gi,
    description: "Credit card CVV (3-4 digits, in context)",
  },
  {
    type: "dangerous_blob_url",
    regex: /URL\.createObjectURL\s*\(/gi,
    description: "Dangerous JavaScript Blob URL creation",
  },
  {
    type: "dangerous_csp_none",
    regex: /Content-Security-Policy[^;]+['"]none['"]/gi,
    description: 'Content-Security-Policy with "none"',
  },
  {
    type: "dangerous_document_write",
    regex: /document\.(write|writeln)\s*\(/gi,
    description: "Dangerous document.write/writeln calls",
  },
  {
    type: "dangerous_eval",
    regex: /\b(?:eval|execScript)\s*\(/gi,
    description: "Dangerous eval/execScript calls",
  },
  {
    type: "dangerous_function",
    regex: /(?:setTimeout|setInterval)\s*\(\s*['"`][^'"`]+['"`]/gi,
    description: "Dangerous setTimeout/setInterval with string",
  },
  {
    type: "dangerous_iframe",
    regex: /<iframe[^>]+src=["'][^"']+["']/gi,
    description: "Iframe with external source",
  },
  {
    type: "dangerous_innerhtml",
    regex: /\.innerHTML\s*=/gi,
    description: "Dangerous innerHTML assignment",
  },
  {
    type: "dangerous_location",
    regex: /location\.(assign|replace)\s*\(/gi,
    description: "Dangerous location.assign/replace calls",
  },
  {
    type: "debug_endpoint",
    regex: /\/debug(?:\/|$)[^\s"']*/gi,
    description: "Debug endpoint URLs (e.g., /debug/, /debug/console)",
  },
  {
    type: "debug_statement",
    regex: /console\.(log|debug|warn|error|trace)\s*\(/gi,
    description: "JavaScript console logging statements",
  },
  {
    type: "digitalocean_personal_access_token",
    regex: /dop_v1_[a-f0-9]{64}/gi,
    description: "DigitalOcean Personal Access Token",
  },
  {
    type: "discord_webhook_url",
    regex: /https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/gi,
    description: "Discord Webhook URL",
  },
  {
    type: "django_flask_secret_key",
    regex: /SECRET_KEY\s*=\s*["']([a-zA-Z0-9\-_]{50,})["']/gi,
    description: "Django/Flask SECRET_KEY (50+ chars, quoted)",
  },
  {
    type: "dotenv_assignment",
    regex: /^[A-Z0-9_]+\s*=\s*(["']?[^"'\n\r]+["']?)$/gim,
    description: ".env variable assignment (KEY=VALUE)",
  },
  {
    type: "email",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    description: "Valid email address",
    validate: (match) => {
      // Exclude common test emails and suspicious domains
      const testEmails = [
        "example@gmail.com",
        "test@example.com",
        "admin@example.com",
      ];
      if (testEmails.includes(match.toLowerCase())) return false;
      // Exclude emails with suspicious TLDs or local domains
      if (/\.(invalid|test|example|local|localhost)$/i.test(match))
        return false;
      // Exclude emails with consecutive dots or starting/ending with dot
      if (/(\.\.)|(^\.)|(\.$)/.test(match)) return false;
      // Exclude emails with < 6 chars before @
      if (match.split("@")[0].length < 6) return false;
      // Exclude emails with only numbers before @
      if (/^[0-9]+@/.test(match)) return false;
      return true;
    },
  },
  {
    type: "encryption_key",
    regex:
      /(?:encryption|aes|rsa|private|public|pgp|gpg)\s*[:=]\s*["']([A-Za-z0-9\/\+=]{16,})["']/gi,
    description: "Encryption key (16+ chars, quoted)",
  },
  {
    type: "api_endpoint",
    regex: /https?:\/\/[^"'\s]+\/(?:api\/v\d+[^"'\s]*|graphql[^"'\s]*)/gi,
    description: "API endpoint (api/vX or graphql)",
  },
  {
    type: "env_variable",
    regex: /process\.env\.[A-Z0-9_]+(?=\s*[;\s}])/gi,
    description: "Node.js environment variable access",
  },
  {
    type: "error_message",
    regex: /(?:Exception|Error|Traceback|Stacktrace)\s*:\s*['"][^'"]+['"]/gi,
    description: "Error message or stack trace",
  },
  {
    type: "event_handler",
    regex: /on(?:click|change|submit|load|error)=["']?([^"']+)["']?/gi,
    description: "HTML event handler attributes",
  },
  {
    type: "express_route",
    regex:
      /app\.(get|post|put|delete|patch|options|head)\s*\(\s*["'][^"']+["']/gi,
    description: "Express.js route definitions",
  },
  {
    type: "facebook_access_token",
    regex: /EAACEdEose0cBA[a-zA-Z0-9]+/gi,
    description: "Facebook Access Token",
  },
  {
    type: "fetch_call",
    regex: /fetch\s*\(\s*["'](https?:\/\/[^"']+)["']/gi,
    description: "JavaScript fetch API calls with URLs",
  },
  {
    type: "file_operation",
    regex:
      /(?:copyFile|fs\.copy|unlink|deleteFile|fs\.unlink|moveFile|fs\.rename|readFile|fs\.read|writeFile|fs\.write)\s*\(/gi,
    description: "Node.js file operations",
  },
  {
    type: "file_execute",
    regex: /(?:exec|spawn|system|popen|shell_exec|passthru|proc_open)\s*\(/gi,
    description: "Shell command execution",
  },
  {
    type: "file_inclusion",
    regex: /(?:require|include|import|load)\s*\(\s*["'][^"']+["']\s*\)/gi,
    description: "File inclusion statements",
  },
  {
    type: "file_upload",
    regex: /(?:input|form)[^>]+type=["']file["']/gi,
    description: "HTML file upload inputs",
  },
  {
    type: "firebase_key",
    regex: /firebase.*[:=]\s*["']([a-zA-Z0-9\-_]{30,100})["']/gi,
    description: "Firebase API key (30-100 chars, quoted)",
  },
  {
    type: "fixme_comment",
    regex: /\/\/\s*FIXME[:]?[^\n\r]*/gi,
    description: "FIXME comments in code",
  },
  {
    type: "flask_route",
    regex: /@app\.route\s*\(\s*["'][^"']+["']\s*\)/gi,
    description: "Flask route decorators",
  },
  {
    type: "gcp_private_key",
    regex:
      /"private_key":\s*"-----BEGIN PRIVATE KEY-----\n[^"]+?\n-----END PRIVATE KEY-----"/gi,
    description: "GCP Private Key in JSON",
  },
  {
    type: "gcp_service_account",
    regex: /"type":\s*"service_account"/gi,
    description: "GCP Service Account JSON type",
  },
  {
    type: "github_token",
    regex: /gh[pur]_[A-Za-z0-9]{36,76}/gi,
    description: "GitHub Personal, App, or Refresh Token",
  },
  {
    type: "google_api_key",
    regex: /AIza[0-9A-Za-z\-_]{35}/gi,
    description: "Google API Key (35 chars)",
  },
  {
    type: "google_oauth_refresh_token",
    regex: /1\/[A-Za-z0-9\-_]{43}/gi,
    description: "Google OAuth Refresh Token",
  },
  {
    type: "google_tag_manager_id",
    regex: /GTM-[A-Z0-9]{4,8}/gi,
    description: "Google Tag Manager ID",
  },
  {
    type: "hardcoded_cred",
    regex:
      /(?:username|user|password|credential)\s*[:=]\s*["']([a-zA-Z0-9\-_@.]{8,})["']/gi,
    description: "Hardcoded credentials (8+ chars, quoted)",
  },
  {
    type: "hardcoded_ip",
    regex:
      /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/gi,
    description: "Valid IPv4 address",
  },
  {
    type: "hardcoded_port",
    regex: /(?:https?:\/\/[^:]+:|^port\s*=\s*)(\d{1,5})/g,
    description: "Valid port number (1-65535)",
    validate: (match) => {
      const port = parseInt(match, 10);
      return (
        port >= 1 && port <= 65535 && !["1", "2", "3", "10"].includes(match)
      ); // Exclude common false positives
    },
  },
  {
    type: "heroku_api_key",
    regex: /[hH]eroku\s*[:=]\s*["']([0-9a-fA-F]{32})["']/gi,
    description: "Heroku API Key (32-char hex, quoted)",
  },
  {
    type: "http_authorization_header",
    regex: /Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=/gi,
    description: "HTTP Bearer Authorization header",
  },
  {
    type: "http_cookie_header",
    regex: /(?:Cookie|Set-Cookie):\s*[^;]+;/gi,
    description: "HTTP Cookie or Set-Cookie header",
  },
  {
    type: "iban",
    regex: /[A-Z]{2}[0-9]{2}[A-Z0-9]{4,30}/g,
    description: "International Bank Account Number",
    validate: (match) => {
      // Check length (min 15, max 34)
      if (match.length < 15 || match.length > 34) return false;
      // Validate country code (2 letters)
      if (!/^[A-Z]{2}/.test(match)) return false;
      // Validate check digits (2 numbers)
      if (!/^[0-9]{2}/.test(match.slice(2, 4))) return false;
      // Basic IBAN checksum (using BigInt for safety)
      const rearranged = match.slice(4) + match.slice(0, 4);
      const numeric = rearranged.replace(/[A-Z]/g, (c) =>
        (c.charCodeAt(0) - 55).toString()
      );
      try {
        return BigInt(numeric) % 97n === 1n;
      } catch {
        return false;
      }
    },
  },
  {
    type: "inline_script",
    regex: /<script[^>]*>(?:[^<]|<(?!\/script>))*<\/script>/gi,
    description: "Inline JavaScript in HTML",
  },
  {
    type: "jwt_token",
    regex: /ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/gi,
    description: "JSON Web Token (header.payload.signature)",
  },
  {
    type: "jwt_operation",
    regex: /jwt\.(decode|sign|verify)\s*\(/gi,
    description: "JWT operations (decode, sign, verify)",
  },
  {
    type: "local_storage",
    regex:
      /(?:localStorage|sessionStorage)\.setItem\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*\)/gi,
    description: "Local/session storage writes",
  },
  {
    type: "mailgun_api_key",
    regex: /key-[0-9a-zA-Z]{32}/gi,
    description: "Mailgun API Key",
  },
  {
    type: "mobile_appcenter_secret",
    regex: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
    description: "Mobile AppCenter Secret (UUID)",
  },
  {
    type: "mongodb_uri",
    regex: /mongodb(?:\+srv)?:\/\/(?:[^:]+:[^@]+@)?[^"'\s]+/gi,
    description: "MongoDB connection URI",
  },
  {
    type: "mysql_uri",
    regex: /mysql:\/\/(?:[^:]+:[^@]+@)?[^"'\s]+/gi,
    description: "MySQL connection URI",
  },
  {
    type: "postgres_uri",
    regex: /postgres(?:ql)?:\/\/(?:[^:]+:[^@]+@)?[^"'\s]+/gi,
    description: "PostgreSQL connection URI",
  },
  {
    type: "oauth_endpoint",
    regex: /\/oauth\/(?:authorize|token)/gi,
    description: "OAuth authorize or token endpoints",
  },
  {
    type: "passport_number",
    regex: /\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b/gi,
    description: "Passport number (US format)",
    validate: (match) => {
      // Exclude all digits or all letters
      if (/^[A-Za-z]+$/.test(match) || /^\d+$/.test(match)) return false;
      // Exclude known test numbers
      const testPassports = ["C1234567", "X0000000"];
      if (testPassports.includes(match)) return false;
      return true;
    },
  },
  {
    type: "payment_provider_url",
    regex:
      /https?:\/\/(?:checkout|api)\.(?:stripe|paypal|squareup|adyen)\.com\/[^\s"']*/gi,
    description: "Payment provider API URLs",
  },
  {
    type: "possible_creds",
    regex:
      /(?:password\s*[:=`"']+\s*[^\s]+|password is\s*[:=`"']*\s*[^\s]+|pwd\s*[:=`"']*\s*[^\s]+|passwd\s*[:=`"']+\s*[^\s]+)/gi,
    description: "Possible credentials assignment (password, pwd, passwd)",
  },
  {
    type: "pem_certificate",
    regex: /-----BEGIN CERTIFICATE-----\n[^-]+\n-----END CERTIFICATE-----/gi,
    description: "PEM certificate",
  },
  {
    type: "paypal_client_id",
    regex: /A[a-zA-Z0-9_-]{38,80}/gi,
    description: "PayPal Client ID (38-80 chars)",
    validate: (match) => {
      // Exclude values with "block", "menu", "canvas", "footer", "header"
      if (/(block|menu|canvas|footer|header|paragraph|view-mode)/i.test(match))
        return false;
      // Exclude values with only hyphens and underscores
      if (/^[-_a-z]+$/i.test(match)) return false;
      return true;
    },
  },
  {
    type: "path_traversal",
    regex: /\.\.\/+/gi,
    description: "Path traversal sequences (../)",
  },
  {
    type: "phone_number",
    regex: /(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/gi,
    description: "Phone number (US/international format)",
    validate: (match) => {
      // Exclude common test numbers and obvious placeholders
      const testNumbers = [
        "1234567890",
        "0000000000",
        "1111111111",
        "5555555555",
        "9999999999",
      ];
      const digits = match.replace(/\D/g, "");
      if (testNumbers.includes(digits)) return false;
      // Exclude numbers with all same digit
      if (/^(\d)\1+$/.test(digits)) return false;
      // Exclude numbers with less than 10 digits
      if (digits.length < 10) return false;
      // Exclude numbers starting with 555 (often used in movies)
      if (/^555/.test(digits)) return false;
      return true;
    },
  },
  {
    type: "private_key",
    regex:
      /-----BEGIN (?:RSA|EC|OPENSSH|ENCRYPTED)? ?PRIVATE KEY-----\n[^-]+\n-----END (?:RSA|EC|OPENSSH|ENCRYPTED)? ?PRIVATE KEY-----/gi,
    description: "Private key (RSA, EC, OpenSSH, or encrypted)",
  },
  {
    type: "query_param",
    regex: /(?:href|src)=["'][^?]+\?([^"']+)/g,
    description: "URL query parameters",
    validate: (match) => {
      // Ensure it’s a key=value pair and not HTML
      if (!match.includes("=") || match.includes("=>")) return false;
      // Exclude matches containing HTML tags or fragments
      if (/<|>|<\/|div|li|ul|nav|hr|class=|button|h3|a\s/i.test(match))
        return false;
      // Exclude matches that are too long (likely not a real param)
      if (match.length > 100) return false;
      return true;
    },
  },
  {
    type: "redis_uri",
    regex: /redis:\/\/(?:[^:]+:[^@]+@)?[^"'\s]+/gi,
    description: "Redis connection URI",
  },
  {
    type: "rsa_public_key",
    regex: /-----BEGIN PUBLIC KEY-----\n[^-]+\n-----END PUBLIC KEY-----/gi,
    description: "RSA public key",
  },
  {
    type: "s3_bucket_url",
    regex:
      /https?:\/\/[a-z0-9\-_\.]+\.s3(?:-[a-z0-9\-]+)?\.amazonaws\.com\/[^\s"']*/gi,
    description: "AWS S3 bucket URL",
  },
  {
    type: "sendgrid_api_key",
    regex: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/gi,
    description: "SendGrid API Key",
  },
  {
    type: "sensitive_comment",
    regex: /<!--\s*(?:secret|password|todo|fixme|debug|remove)[^\n\r>]*-->/gi,
    description: "Sensitive HTML comments",
  },
  {
    type: "sensitive_cookie_name",
    regex:
      /(?:sessionid|auth_token|jwt|access_token|refresh_token|sid)=[^;\s]+/gi,
    description: "Sensitive cookie names",
  },
  {
    type: "sensitive_file_path",
    regex: /\/etc\/(?:passwd|shadow|group)/gi,
    description: "Sensitive Unix file paths",
  },
  {
    type: "sensitive_html_attribute",
    regex:
      /data-(?:secret|token|key|password|auth)[a-zA-Z0-9\-]*=["'][^"']+["']/gi,
    description: "Sensitive HTML data attributes",
  },
  {
    type: "session_id",
    regex: /session_id\s*[:=]\s*["']([a-zA-Z0-9\-_]{16,64})["']/gi,
    description: "Session ID (16-64 chars, quoted)",
  },
  {
    type: "slack_webhook_url",
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\/\-]+/gi,
    description: "Slack Webhook URL",
  },
  {
    type: "slack_token",
    regex: /xox[bpao]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}/gi,
    description: "Slack Token (bot, user, app, or workspace)",
  },
  {
    type: "sql_query",
    regex: /\bSELECT\s+.*?\bFROM\s+[^\s;]+/gi,
    description: "SQL SELECT queries",
    validate: (match) => {
      // Exclude queries with only SELECT * FROM or missing table name
      if (/SELECT\s+\*\s+FROM\s*;?$/i.test(match)) return false;
      // Exclude queries with suspiciously short table names
      const tableMatch = match.match(/\bFROM\s+([^\s;]+)/i);
      if (tableMatch && tableMatch[1].length < 3) return false;
      // Exclude queries with only keywords and no real table
      if (/FROM\s+(dual|null|true|false)/i.test(match)) return false;
      return true;
    },
  },
  {
    type: "ssn",
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/gi,
    description: "US Social Security Number (XXX-XX-XXXX)",
    validate: (match) => {
      // Exclude known fake/test SSNs
      const testSSNs = ["123-45-6789", "078-05-1120", "219-09-9999"];
      if (testSSNs.includes(match)) return false;
      // Exclude all same digit
      if (/^(\d)\1{2}-(\d)\2{1}-(\d)\3{3}$/.test(match)) return false;
      return true;
    },
  },
  {
    type: "ssrf_vector",
    regex: /\b(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)\b/gi,
    description: "SSRF vectors (localhost, loopback IPs)",
  },
  {
    type: "stripe_key",
    regex: /(?:pk|sk|rk)_[live|test]_[0-9a-zA-Z]{24}/gi,
    description: "Stripe API Key (publishable or secret)",
  },
  {
    type: "swift_code",
    regex: /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b/g,
    description: "SWIFT/BIC Code (8 or 11 chars, uppercase only, word-bounded)",
    validate: (match) => {
      if (match.length !== 8 && match.length !== 11) return false;
      // Ensure first 4 chars are uppercase letters (bank code)
      if (!/^[A-Z]{4}/.test(match)) return false;
      // Ensure chars 5-6 are uppercase letters (country code)
      if (!/^[A-Z]{2}/.test(match.slice(4, 6))) return false;
      // Ensure chars 7-8 are alphanumeric (location code)
      if (!/^[A-Z0-9]{2}/.test(match.slice(6, 8))) return false;
      // If 11 chars, ensure last 3 are alphanumeric (branch code)
      if (match.length === 11 && !/^[A-Z0-9]{3}/.test(match.slice(8, 11)))
        return false;
      // Exclude common false positives (e.g., generic words)
      const falsePositives = [
        "YYYYMMDD",
        "SSSSSSSS",
        "DATETIME",
        "PASSWORD",
        "POSITION",
        "CLICKCEA",
        "NOSCRIPT",
        "TRACKING",
        "JAVASCRI",
        "DOCUMENT",
        "FUNCTION",
        "LOCATION",
        "ONBOARDI",
        "RESOURCE",
        "SUBSCRIB",
        "CONTAINE",
        "IMPORTAN",
        "CONTROLL",
      ];
      return !falsePositives.includes(match);
    },
  },
  {
    type: "temporary_credential",
    regex:
      /temp(?:orary)?[_-]*(?:key|token|secret|password)\s*[:=]\s*["']([a-zA-Z0-9\-_\.]{16,})["']/gi,
    description: "Temporary credentials (16+ chars, quoted)",
  },
  {
    type: "test_endpoint",
    regex: /\/test(?:\/|$)[^\s"']*/gi,
    description: "Test endpoint URLs (e.g., /test/, /test/api)",
  },
  {
    type: "third_party_api_key",
    regex:
      /(?:sendgrid|mailgun|twilio|stripe|paypal|github|slack|discord|asana|digitalocean)\s*[:=]\s*["']([a-zA-Z0-9\-_\.]{16,})["']/gi,
    description: "Third-party API keys (16+ chars, quoted)",
  },
  {
    type: "todo_comment",
    regex: /\/\/\s*TODO[:]?[^\n\r]*/gi,
    description: "TODO comments in code",
  },
  {
    type: "twilio_api_key",
    regex: /SK[0-9a-fA-F]{32}/gi,
    description: "Twilio API Key",
  },
  {
    type: "user_2fa",
    regex: /(?:twoFactor|2fa|multiFactor)\s*[:=]\s*[^\s;]+/gi,
    description: "2FA or MFA configurations",
  },
  {
    type: "user_activation",
    regex: /activate(?:User|Account|Member)\s*\(/gi,
    description: "User activation function calls",
  },
  {
    type: "user_audit_log",
    regex: /audit(?:Log|Trail)\s*[:=]\s*[^\s;]+/gi,
    description: "Audit log configurations",
  },
  {
    type: "user_approve",
    regex: /approve(?:User|Account|Member)\s*\(/gi,
    description: "User approval function calls",
  },
  {
    type: "user_auth_middleware",
    regex: /(?:isAuthenticated|requireAuth|ensureAuth)\s*\(/gi,
    description: "Authentication middleware",
  },
  {
    type: "user_authorization_middleware",
    regex: /(?:isAuthorized|requireRole|checkPermission)\s*\(/gi,
    description: "Authorization middleware",
  },
  {
    type: "user_ban",
    regex: /ban(?:User|Account|Member)\s*\(/gi,
    description: "User ban function calls",
  },
  {
    type: "user_block",
    regex: /block(?:User|Account|Member)\s*\(/gi,
    description: "User block function calls",
  },
  {
    type: "user_deactivation",
    regex: /deactivate(?:User|Account|Member)\s*\(/gi,
    description: "User deactivation function calls",
  },
  {
    type: "user_delete",
    regex: /delete\s*\(\s*["'][0-9A-Za-z\-_@.]+["']\s*\)/gi,
    description: "User delete function calls",
  },
  {
    type: "user_email_verification",
    regex: /verify(?:Email|UserEmail)\s*\(/gi,
    description: "Email verification function calls",
  },
  {
    type: "user_invite",
    regex: /invite(?:User|Member|Account)\s*\(/gi,
    description: "User invite function calls",
  },
  {
    type: "user_login",
    regex: /login(?:User|Account|Member)?\s*\(/gi,
    description: "User login function calls",
  },
  {
    type: "user_logout",
    regex: /logout(?:User|Account|Member)?\s*\(/gi,
    description: "User logout function calls",
  },
  {
    type: "user_notification",
    regex: /send(?:Notification|Alert|Message)\s*\(/gi,
    description: "User notification function calls",
  },
  {
    type: "user_password_reset",
    regex: /reset(?:Pass(?:word)?|Pwd)\s*\(/gi,
    description: "Password reset function calls",
  },
  {
    type: "user_payment",
    regex: /process(?:Payment|Refund|Charge)\s*\(/gi,
    description: "Payment processing function calls",
  },
  {
    type: "user_permission_check",
    regex: /can(?:Access|Edit|Delete|View|Create)\s*\(/gi,
    description: "Permission check function calls",
  },
  {
    type: "user_profile_update",
    regex: /update(?:Profile|User|Account)\s*\(/gi,
    description: "Profile update function calls",
  },
  {
    type: "user_reject",
    regex: /reject(?:User|Account|Member)/gi,
    description: "User rejection function calls",
  },
  {
    type: "user_registration",
    regex: /register\s*\(\s*["'][0-9A-Za-z\-_@.]+["']\s*\)/gi,
    description: "User registration function calls",
  },
  {
    type: "user_role_assignment",
    regex: /assign(?:Role|Permission)\s*\(/gi,
    description: "Role/permission assignment function calls",
  },
  {
    type: "user_role_check",
    regex: /has(?:Role|Permission)\s*\(/gi,
    description: "Role/permission check function calls",
  },
  {
    type: "user_session_check",
    regex: /check(?:Session|UserSession|AuthSession)/gi,
    description: "Session check function calls",
  },
  {
    type: "user_subscription",
    regex: /subscribe\s*\(\s*["'][0-9A-Za-z\-_@.]+["']\s*\)/gi,
    description: "User subscription function calls",
  },
  {
    type: "user_suspend",
    regex: /suspend(?:User|Account|Member)/gi,
    description: "User suspension function calls",
  },
  {
    type: "user_transaction",
    regex: /create(?:Transaction|Order|Payment)/gi,
    description: "Transaction creation function calls",
  },
  {
    type: "user_unban",
    regex: /unban(?:User|Account|Member)/gi,
    description: "User unban function calls",
  },
  {
    type: "user_unblock",
    regex: /unblock(?:User|Account|Member)/gi,
    description: "User unblock function calls",
  },
  {
    type: "user_unsuspend",
    regex: /unsuspend(?:User|Account)/gi,
    description: "User unsuspend function calls",
  },
  {
    type: "windows_sensitive_file_path",
    regex: /C:\\Windows\\System32\\config\\SAM/gi,
    description: "Windows sensitive file path (SAM)",
  },
  {
    type: "x_frame_options_allow",
    regex: /X-Frame-Options:\s*ALLOWALL/gi,
    description: "X-Frame-Options ALLOWALL",
  },
  {
    type: "xss_payload",
    regex: /<img[^>]+src=["'][^"']*onerror\s*=/gi,
    description: "Potential XSS payload in img tag",
  },
];

// XSS sinks (unchanged, retained for completeness)
const xssSinks = [
  "eval",
  "setTimeout",
  "setInterval",
  "Function",
  "execScript",
  "document.write",
  "document.writeln",
  "innerHTML",
  "outerHTML",
  "insertAdjacentHTML",
  "insertBefore",
  "appendChild",
  "replaceChild",
  "createElement",
  "document.createElement",
  "setAttribute",
  "window.open",
  "location.assign",
  "location.replace",
  "location.href",
  "location",
  "window.location",
  "window.location.href",
  "window.location.assign",
  "window.location.replace",
  "window.location.reload",
  "window.name",
  "window.parent",
  "window.top",
  "window.frames",
  "window.postMessage",
  "window.onerror",
  "window.onmessage",
  "window.onhashchange",
  "window.onpopstate",
  "window.history.pushState",
  "window.history.replaceState",
  "document.cookie",
  "document.domain",
  "document.referrer",
  "document.URL",
  "document.baseURI",
  "document.location",
  "document.forms",
  "document.scripts",
  "document.getElementById",
  "document.getElementsByTagName",
  "document.getElementsByClassName",
  "document.querySelector",
  "document.querySelectorAll",
  "document.body",
  "document.head",
  "document.createTextNode",
  "document.createComment",
  "document.importNode",
  "document.adoptNode",
  "document.implementation.createHTMLDocument",
  "document.execCommand",
  "document.designMode",
  "document.open",
  "document.close",
  "document.attachEvent",
  "document.detachEvent",
  "document.addEventListener",
  "document.removeEventListener",
  "window.alert",
  "window.confirm",
  "window.prompt",
  "window.print",
  "window.scroll",
  "window.scrollTo",
  "window.scrollBy",
  "window.setImmediate",
  "window.clearImmediate",
  "window.setInterval",
  "window.clearInterval",
  "window.setTimeout",
  "window.clearTimeout",
  "window.XMLHttpRequest",
  "window.fetch",
  "window.WebSocket",
  "window.Worker",
  "window.SharedWorker",
  "window.ServiceWorker",
  "window.Blob",
  "window.FileReader",
  "window.URL.createObjectURL",
  "window.URL.revokeObjectURL",
  "window.navigator.sendBeacon",
  "window.navigator.registerProtocolHandler",
  "window.navigator.clipboard.writeText",
  "window.navigator.clipboard.readText",
  "window.localStorage.setItem",
  "window.sessionStorage.setItem",
  "window.indexedDB.open",
  "window.openDatabase",
  "window.crypto.subtle",
  "window.crypto.getRandomValues",
  "window.Notification",
  "window.showModalDialog",
  "window.attachEvent",
  "window.detachEvent",
  "window.addEventListener",
  "window.removeEventListener",
  "window.dispatchEvent",
  "window.customElements.define",
  "window.customElements.get",
  "window.customElements.whenDefined",
  // Event handler attributes
  "onerror",
  "onload",
  "onclick",
  "onchange",
  "onsubmit",
];

// User functionalities (expanded for bug bounty context)
const userFunctionalities = [
  // Core user interaction
  "forms",
  "inputs",
  "auth_fields",
  "search_fields",
  "event_listeners",
  "hidden_inputs",
  "buttons",
  "textareas",
  "selects",
  "checkboxes",
  "radios",
  "file_inputs",
  "submit_buttons",
  "links",
  "iframes",
  "scripts",
  "meta_tags",
  "cookies",
  "local_storage",
  "session_storage",
  "modals",
  "popups",
  "dialogs",
  "nav_menus",
  "dropdowns",
  "tabs",
  "accordions",
  "carousels",
  "tooltips",
  "notifications",
  // API and endpoints
  "api_calls",
  "graphql_queries",
  "rest_endpoints",
  "admin_routes",
  // Auth flows
  "login_forms",
  "signup_forms",
  "password_resets",
  "profile_fields",
  "comment_fields",
  "upload_forms",
  "payment_fields",
  "csrf_tokens",
  // Dynamic/script features
  "dynamic_scripts",
  "inline_styles",
  "data_attributes",
  // Bug bounty/attack surface
  "oauth_buttons",
  "sso_buttons",
  "file_downloaders",
  "cors_headers",
  "csp_headers",
  "jwt_tokens",
  "analytics_scripts",
  "error_messages",
  "exposed_keys",
  "exposed_tokens",
  "debug_panels",
  "feature_flags",
  "rate_limiters",
  "captcha_widgets",
  "websocket_endpoints",
  "service_workers",
  "manifest_links",
  "pwa_features",
  "third_party_scripts",
  "iframe_sandbox",
  "mixed_content",
  "deprecated_features",
  "password_strength_meters",
  "auto_complete_fields",
  "remember_me",
  "forgot_password_links",
  "email_verification_links",
  "mobile_app_links",
  "social_login_buttons",
  "privacy_policy_links",
  "terms_of_service_links",
  "contact_links",
  "support_chat_widgets",
  "user_avatar_uploads",
  "user_settings_links",
  "user_logout_links",
  "user_delete_account_links",
  "user_export_data_links",
  "user_import_data_links",
  "user_notification_settings",
  "user_two_factor_settings",
  "user_api_token_fields",
  "user_billing_links",
  "user_subscription_links",
  "user_referral_links",
  "user_affiliate_links",
  "user_reward_links",
  "user_points_fields",
  "user_badge_fields",
  "user_achievement_fields",
  "user_feedback_forms",
  "user_report_forms",
  "user_support_ticket_forms",
  "user_alerts",
  "user_announcements",
  "user_wishlist",
  "user_referrals",
  "user_affiliates",
  "user_rewards",
  "user_points",
  "user_badges",
  "user_achievements",
];

// Entropy calculation
function calculateEntropy(str) {
  if (!str) return 0;
  const len = str.length;
  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  return -Object.values(freq).reduce(
    (sum, f) => sum + (f / len) * Math.log2(f / len),
    0
  );
}

// Enhanced false positive filtering
function isFalsePositive(value) {
  if (!value) return true;
  const falsePositives = [
    /example\.com/i,
    /test/i,
    /demo/i,
    /localhost/i,
    /^1234567890$/,
    /^([0-9])\1+$/, // Repeating digits
    /^([a-zA-Z])\1+$/i, // Repeating letters
  ];
  return falsePositives.some((regex) => regex.test(value));
}

// DNS resolution with fallback
async function resolveUrl(url) {
  try {
    await dns.lookup(new URL(url).hostname);
    return url;
  } catch (e) {
    await logError(`DNS resolution failed: ${url}`, { error: e.message });
    return "https://1.1.1.1";
  }
}

// Cleanup temp profile
async function cleanupTemp() {
  const tempDir = path.join(
    process.env.TEMP || "/tmp",
    "puppeteer_dev_chrome_profile"
  );
  try {
    await fs.rm(tempDir, { recursive: true, force: true });
    console.log("[*] Cleared temp profile");
  } catch (e) {
    await logError(`Temp cleanup failed: ${e.message}`);
  }
}

// Wait for frame stability
async function waitForFrameStability(page) {
  try {
    await page.waitForFunction(
      () => {
        return (
          document.querySelectorAll("iframe").length === document.frames.length
        );
      },
      { timeout: 60000 }
    );
  } catch (e) {
    await logError(`Frame stability wait failed: ${e.message}`);
  }
}

// Enhanced regex extraction with batch processing
async function extractSensitiveData(jsLinks, outputDir) {
  const results = { sensitive: [] };
  const batchSize = threads;
  const baseHost = (() => {
    try {
      return new URL(url).hostname;
    } catch {
      return null;
    }
  })();
  const normalizeAbs = (u) => {
    try {
      const abs = new URL(u, url);
      abs.hash = "";
      if (abs.search && abs.search.length > 1) {
        const params = Array.from(new URLSearchParams(abs.search));
        params.sort(([a], [b]) => (a > b ? 1 : a < b ? -1 : 0));
        abs.search = params.length
          ? "?" + params.map(([k, v]) => `${k}=${v}`).join("&")
          : "";
      }
      return abs.toString();
    } catch {
      return null;
    }
  };
  const linksToFetch = Array.from(
    new Set(
      jsLinks
        .map((l) => normalizeAbs(l))
        .filter(
          (u) =>
            u &&
            /^https?:\/\//i.test(u) &&
            (!baseHost || new URL(u).hostname === baseHost)
        )
    )
  );
  for (let i = 0; i < linksToFetch.length; i += batchSize) {
    const batch = linksToFetch.slice(i, i + batchSize);
    const promises = batch.map(async (link) => {
      try {
        console.log(`[*] Fetching JS file: ${link}`);
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 15000);
        const response = await fetch(link, {
          headers:
            headers.length > 0
              ? headers[Math.floor(Math.random() * headers.length)]
              : {},
          signal: controller.signal,
        });
        clearTimeout(timeoutId);
        if (!response.ok) {
          await logError(`Failed to fetch ${link}: ${response.status}`, {
            url: link,
          });
          return;
        }
        const content = await response.text();
        const lines = content.split("\n");

        for (const pattern of sensitivePatterns) {
          let match;
          while ((match = pattern.regex.exec(content)) !== null) {
            const value = match[1] || match[0];
            const entropy = calculateEntropy(value);
            const isValid = pattern.validate ? pattern.validate(value) : true;
            if (
              entropy > entropyThreshold &&
              !isFalsePositive(value) &&
              isValid
            ) {
              const line_number =
                lines.findIndex((line) => line.includes(value)) + 1;
              results.sensitive.push({
                type: pattern.type,
                value,
                link,
                line_number,
              });
            }
          }
        }
      } catch (err) {
        await logError(`Error processing ${link}: ${err.message}`, {
          url: link,
        });
      }
    });
    await Promise.all(promises);
    await new Promise((resolve) => setTimeout(resolve, delay * 1000));
  }

  // Deduplicate
  results.sensitive = Array.from(
    new Set(results.sensitive.map(JSON.stringify))
  ).map((str) => JSON.parse(str));

  // Save output
  const outputFile = path.join(outputDir, "js_data.json");
  try {
    await fs.writeFile(outputFile, JSON.stringify(results, null, 2), "utf8");
    console.log(`[*] Sensitive data saved to ${outputFile}`);
  } catch (e) {
    await logError(`Failed to save output: ${e.message}`, { file: outputFile });
  }
  return results;
}

// Main extraction function
async function extractJsData() {
  let browser = null;
  try {
    await fs.mkdir(outputDir, { recursive: true });

    if (mode === "regex") {
      return await extractSensitiveData(jsLinks, outputDir);
    }

    await cleanupTemp();
    browser = await puppeteerExtra.launch({
      headless: true,
      timeout: 600000,
      protocolTimeout: 360000,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        loginCreds.proxy ? `--proxy-server=${loginCreds.proxy}` : "",
        "--disable-web-security",
        "--disable-gpu", // Reduce GPU usage
        "--disable-dev-shm-usage", // Avoid shared memory issues
      ].filter(Boolean),
    });
    const page = await browser.newPage();

    if (loginCreds.proxy) {
      await page.setRequestInterception(true);
      page.on("request", (request) => request.continue());
    }

    if (userAgents.length > 0) {
      await page.setUserAgent(
        userAgents[Math.floor(Math.random() * userAgents.length)]
      );
    }

    if (headers.length > 0) {
      await page.setExtraHTTPHeaders(
        headers[Math.floor(Math.random() * headers.length)]
      );
    }

    if (loginCreds.username && loginCreds.password) {
      try {
        await page.goto(url, { waitUntil: "networkidle2", timeout: 600000 });
        const loginForm = await page.$(
          'form[id*="login"], form[id*="auth"], form[action*="login"]'
        );
        if (loginForm) {
          await page.type(
            'input[name*="username"], input[name*="email"], input[id*="username"], input[id*="email"]',
            loginCreds.username
          );
          await page.type(
            'input[name*="password"], input[id*="password"]',
            loginCreds.password
          );
          await Promise.all([
            page.click('button[type="submit"], input[type="submit"]'),
            page
              .waitForNavigation({ waitUntil: "networkidle2", timeout: 600000 })
              .catch(() => {}),
          ]);
          console.log(`[*] Attempted login with credentials`);
        }
      } catch (e) {
        await logError(`Authentication failed: ${e.message}`, { url });
      }
    }

    let navigated = false;
    for (let attempt = 1; attempt <= 5; attempt++) {
      try {
        const resolvedUrl = await resolveUrl(url);
        await page.goto(resolvedUrl, { waitUntil: "load", timeout: 600000 });
        await page.evaluate(
          () => new Promise((resolve) => setTimeout(resolve, 10000))
        );
        await page.waitForSelector("body", { timeout: 600000 });
        await waitForFrameStability(page);
        navigated = true;
        break;
      } catch (e) {
        await logError(
          `Navigation attempt ${attempt}/5 failed for ${url}: ${e.message}`,
          { attempt, url }
        );
        if (attempt < 5) {
          await new Promise((resolve) =>
            setTimeout(resolve, 10000 * Math.pow(2, attempt))
          ); // Exponential backoff
        }
      }
    }
    if (!navigated) {
      throw new Error(`All navigation attempts failed for ${url}`);
    }

    try {
      await page.evaluate(() => {
        window.scrollTo(0, document.body.scrollHeight);
      });
      await page.waitForSelector(
        'form, input, textarea, button, [role="dialog"], [data-modal]',
        { timeout: 600000 }
      );
    } catch (e) {
      await logError(`Dynamic content wait failed: ${e.message}`);
    }

    let domData = userFunctionalities.reduce(
      (acc, func) => ({ ...acc, [func]: [] }),
      {}
    );

    if (mode === "enumerate") {
      // --- Dynamic event listener instrumentation ---
      // This script monkey-patches addEventListener/removeEventListener to record all dynamic listeners
      await page.evaluateOnNewDocument(() => {
        window.__dynamicEventListeners = [];
        const origAdd = EventTarget.prototype.addEventListener;
        const origRemove = EventTarget.prototype.removeEventListener;
        EventTarget.prototype.addEventListener = function (
          type,
          listener,
          options
        ) {
          try {
            window.__dynamicEventListeners.push({
              target: this.tagName ? this.tagName.toLowerCase() : "unknown",
              id: this.id || "",
              type,
              listener: listener && listener.name ? listener.name : "anonymous",
              options: options || null,
            });
          } catch (e) {}
          return origAdd.apply(this, arguments);
        };
        EventTarget.prototype.removeEventListener = function (
          type,
          listener,
          options
        ) {
          // Optionally, remove from __dynamicEventListeners if needed
          return origRemove.apply(this, arguments);
        };
      });
      // --- End dynamic event listener instrumentation ---
      for (let attempt = 1; attempt <= 5; attempt++) {
        try {
          domData = await page.evaluate((functionalities) => {
            if (!document.body) throw new Error("Document body not loaded");
            const results = {};
            functionalities.forEach((func) => {
              results[func] = [];
            });

            //Helper to deduplicate arrays of obejct
            const deduplicate = (arr, key) => {
              const seen = new Set();
              return arr.filter((item) => {
                const val = JSON.stringify(item[key] || item);
                if (seen.has(val)) return false;
                seen.add(val);
                return true;
              });
            };

            const observeLazyLoad = () => {
              return new Promise((resolve) => {
                const observer = new IntersectionObserver((entries) => {
                  entries.forEach((entry) => {
                    if (entry.isIntersecting)
                      entry.target.dispatchEvent(new Event("appear"));
                  });
                });
                document
                  .querySelectorAll("div, section, article")
                  .forEach((el) => observer.observe(el));
                setTimeout(() => {
                  observer.disconnect();
                  resolve();
                }, 5000);
              });
            };
            observeLazyLoad();

            // DOM scraping logic (refactored for maintainability and extensibility)
            const domMap = {
              forms: () =>
                Array.from(
                  document.querySelectorAll('form, [data-form], [role="form"]')
                ).map((f) => ({
                  action: f.action || f.getAttribute("data-action") || "",
                  method: f.method || f.getAttribute("data-method") || "GET",
                  inputs: Array.from(
                    f.querySelectorAll("input, textarea, select")
                  ).map((i) => ({
                    name: i.name || "",
                    type: i.type || "text",
                    id: i.id || "",
                  })),
                })),
              inputs: () =>
                Array.from(document.querySelectorAll("input")).map((i) => ({
                  name: i.name || "",
                  type: i.type || "text",
                  id: i.id || "",
                  value: i.value || "",
                  hidden: i.type === "hidden",
                })),
              auth_fields: () =>
                Array.from(
                  document.querySelectorAll(
                    '[name*="auth"],[id*="auth"],[name*="login"],[name*="password"],[id*="user"]'
                  )
                ).map((e) => ({
                  name: e.name || "",
                  id: e.id || "",
                  type: e.type || "text",
                })),
              search_fields: () =>
                Array.from(
                  document.querySelectorAll(
                    '[name*="search"],[id*="search"],[placeholder*="search"]'
                  )
                ).map((e) => ({
                  name: e.name || "",
                  id: e.id || "",
                  type: e.type || "text",
                })),
              event_listeners: () => {
                // Inline event listeners
                const inline = Array.from(
                  document.querySelectorAll("*")
                ).reduce((acc, el) => {
                  const events = [];
                  for (let prop in el) {
                    if (prop.startsWith("on") && el[prop]) {
                      events.push(prop);
                    }
                  }
                  if (events.length) {
                    acc.push({
                      tag: el.tagName.toLowerCase(),
                      id: el.id || "",
                      events,
                    });
                  }
                  return acc;
                }, []);
                // Dynamically attached listeners (best effort)
                // This is a placeholder; true dynamic listener extraction requires instrumentation
                return inline;
              },
              // ... (rest of domMap as in previous message)
            };
            // Extract all user functionalities using domMap
            for (const func of Object.keys(domMap)) {
              try {
                results[func] = domMap[func]() || [];
              } catch (e) {
                results[func] = [];
              }
            }
            results.forms = Array.from(
              document.querySelectorAll('form, [data-form], [role="form"]')
            ).map((f) => ({
              action: f.action || f.getAttribute("data-action") || "",
              method: f.method || f.getAttribute("data-method") || "GET",
              inputs: Array.from(
                f.querySelectorAll("input, textarea, select")
              ).map((i) => ({
                name: i.name || "",
                type: i.type || "text",
                id: i.id || "",
              })),
            }));

            results.inputs = Array.from(document.querySelectorAll("input")).map(
              (i) => ({
                name: i.name || "",
                type: i.type || "text",
                id: i.id || "",
                value: i.value || "",
                hidden: i.type === "hidden",
              })
            );

            results.auth_fields = Array.from(
              document.querySelectorAll(
                '[name*="auth"],[id*="auth"],[name*="login"],[name*="password"],[id*="user"]'
              )
            ).map((e) => ({
              name: e.name || "",
              id: e.id || "",
              type: e.type || "text",
            }));

            results.search_fields = Array.from(
              document.querySelectorAll(
                '[name*="search"],[id*="search"],[placeholder*="search"]'
              )
            ).map((e) => ({
              name: e.name || "",
              id: e.id || "",
              type: e.type || "text",
            }));

            results.event_listeners = Array.from(
              document.querySelectorAll("*")
            ).reduce((acc, el) => {
              const events = [];
              for (let prop in el) {
                if (prop.startsWith("on") && el[prop]) {
                  events.push(prop);
                }
              }
              if (events.length) {
                acc.push({
                  tag: el.tagName.toLowerCase(),
                  id: el.id || "",
                  events,
                });
              }
              return acc;
            }, []);

            results.hidden_inputs = Array.from(
              document.querySelectorAll('input[type="hidden"]')
            ).map((i) => ({
              name: i.name || "",
              value: i.value || "",
              id: i.id || "",
            }));

            results.buttons = Array.from(
              document.querySelectorAll("button")
            ).map((b) => ({
              id: b.id || "",
              type: b.type || "button",
              text: b.innerText.trim() || "",
            }));

            results.textareas = Array.from(
              document.querySelectorAll("textarea")
            ).map((t) => ({
              name: t.name || "",
              id: t.id || "",
              value: t.value || "",
            }));

            results.selects = Array.from(
              document.querySelectorAll("select")
            ).map((s) => ({
              name: s.name || "",
              id: s.id || "",
              options: Array.from(s.options)
                .map((o) => o.value)
                .filter((v) => v),
            }));

            results.checkboxes = Array.from(
              document.querySelectorAll('input[type="checkbox"]')
            ).map((c) => ({
              name: c.name || "",
              id: c.id || "",
              checked: c.checked,
            }));

            results.radios = Array.from(
              document.querySelectorAll('input[type="radio"]')
            ).map((r) => ({
              name: r.name || "",
              id: r.id || "",
              checked: r.checked,
            }));

            results.file_inputs = Array.from(
              document.querySelectorAll('input[type="file"]')
            ).map((f) => ({
              name: f.name || "",
              id: f.id || "",
            }));

            results.submit_buttons = Array.from(
              document.querySelectorAll(
                'input[type="submit"],button[type="submit"]'
              )
            ).map((s) => ({
              name: s.name || "",
              id: s.id || "",
              value: s.value || s.innerText.trim(),
            }));

            results.links = Array.from(document.querySelectorAll("a")).map(
              (a) => ({
                href: a.href || "",
                text: a.innerText.trim() || "",
              })
            );

            results.iframes = Array.from(
              document.querySelectorAll("iframe")
            ).map((i) => ({
              src: i.src || "",
              id: i.id || "",
            }));

            results.scripts = Array.from(
              document.querySelectorAll("script")
            ).map((s) => ({
              src: s.src || "",
              inline: s.innerHTML.length > 0,
            }));

            results.meta_tags = Array.from(
              document.querySelectorAll("meta")
            ).map((m) => ({
              name: m.name || "",
              content: m.content || "",
            }));

            results.cookies = [
              ...new Set(
                document.cookie
                  .split(";")
                  .map((c) => c.trim())
                  .filter((c) => c)
              ),
            ];

            results.local_storage = Object.entries(localStorage)
              .filter(([k, v]) => v)
              .map(([k, v]) => ({ key: k, value: v }));

            results.session_storage = Object.entries(sessionStorage)
              .filter(([k, v]) => v)
              .map(([k, v]) => ({ key: k, value: v }));

            results.modals = Array.from(
              document.querySelectorAll('[role="dialog"], .modal, [data-modal]')
            ).map((m) => ({
              id: m.id || "",
              visible: !m.hidden,
            }));

            results.popups = Array.from(
              document.querySelectorAll(".popup, [data-popup]")
            ).map((p) => ({
              id: p.id || "",
              visible: !p.hidden,
            }));

            results.dialogs = Array.from(
              document.querySelectorAll("dialog")
            ).map((d) => ({
              id: d.id || "",
              open: d.open,
            }));

            results.nav_menus = Array.from(
              document.querySelectorAll('nav, [role="navigation"]')
            ).map((n) => ({
              id: n.id || "",
              links: Array.from(n.querySelectorAll("a")).map((a) => a.href),
            }));

            results.dropdowns = Array.from(
              document.querySelectorAll("select, [data-dropdown]")
            ).map((d) => ({
              id: d.id || "",
              options: Array.from(d.querySelectorAll("option"))
                .map((o) => o.value)
                .filter((v) => v),
            }));

            results.tabs = Array.from(
              document.querySelectorAll('[role="tablist"]')
            ).map((t) => ({
              id: t.id || "",
              tabs: Array.from(t.querySelectorAll('[role="tab"]')).map(
                (tab) => tab.id || ""
              ),
            }));

            results.accordions = Array.from(
              document.querySelectorAll("[data-accordion], .accordion")
            ).map((a) => ({
              id: a.id || "",
              sections: Array.from(a.querySelectorAll("[data-section]")).map(
                (s) => s.id || ""
              ),
            }));

            results.carousels = Array.from(
              document.querySelectorAll(".carousel, [data-carousel]")
            ).map((c) => ({
              id: c.id || "",
              items: Array.from(c.querySelectorAll("[data-item]")).map(
                (i) => i.id || ""
              ),
            }));

            results.tooltips = Array.from(
              document.querySelectorAll("[data-tooltip], .tooltip")
            ).map((t) => ({
              id: t.id || "",
              content: t.getAttribute("data-tooltip") || "",
            }));

            results.notifications = Array.from(
              document.querySelectorAll(".notification, [data-notification]")
            ).map((n) => ({
              id: n.id || "",
              content: n.innerText.trim() || "",
            }));

            const resolveAbs = (u) => {
              try {
                return new URL(u, location.href).toString();
              } catch (e) {
                return null;
              }
            };
            results.api_calls = Array.from(
              document.querySelectorAll("script")
            ).reduce((acc, s) => {
              const matches =
                s.innerHTML.match(
                  /fetch\(\s*["']([^"']+)["']\s*\)|XMLHttpRequest\.open\(\s*["'](?:GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+)["']\s*\)/g
                ) || [];
              matches.forEach((m) => {
                const candidate = (m.match(/["']([^"']+)["']/) || [])[1];
                const abs = candidate ? resolveAbs(candidate) : null;
                if (
                  abs &&
                  (candidate.includes("/api") ||
                    candidate.includes("/graphql")) &&
                  new URL(abs).hostname === location.hostname
                ) {
                  acc.push(abs);
                }
              });
              return acc;
            }, []);

            results.graphql_queries = Array.from(
              document.querySelectorAll("script")
            ).reduce((acc, s) => {
              const matches =
                s.innerHTML.match(/query\s*{[^}]+}|mutation\s*{[^}]+}/g) || [];
              acc.push(...matches);
              return acc;
            }, []);

            results.rest_endpoints = results.api_calls.filter(
              (url) => url.includes("/api") && !url.includes("/graphql")
            );

            results.admin_routes = results.links
              .filter((l) => l.href && l.href.includes("/admin"))
              .map((l) => l.href);

            results.login_forms = Array.from(
              document.querySelectorAll(
                'form[id*="login"], form[action*="login"]'
              )
            ).map((f) => ({
              action: f.action || "",
              inputs: Array.from(f.querySelectorAll("input")).map(
                (i) => i.name
              ),
            }));

            results.signup_forms = Array.from(
              document.querySelectorAll(
                'form[id*="signup"], form[action*="signup"]'
              )
            ).map((f) => ({
              action: f.action || "",
              inputs: Array.from(f.querySelectorAll("input")).map(
                (i) => i.name
              ),
            }));

            results.password_resets = Array.from(
              document.querySelectorAll(
                'form[id*="reset"], form[action*="reset"]'
              )
            ).map((f) => ({
              action: f.action || "",
              inputs: Array.from(f.querySelectorAll("input")).map(
                (i) => i.name
              ),
            }));

            results.profile_fields = Array.from(
              document.querySelectorAll('[name*="profile"], [id*="profile"]')
            ).map((p) => ({
              name: p.name || "",
              id: p.id || "",
            }));

            results.comment_fields = Array.from(
              document.querySelectorAll('[name*="comment"], [id*="comment"]')
            ).map((c) => ({
              name: c.name || "",
              id: c.id || "",
            }));

            results.upload_forms = Array.from(
              document.querySelectorAll('form[action*="upload"]')
            ).map((f) => ({
              action: f.action || "",
              inputs: Array.from(f.querySelectorAll("input")).map(
                (i) => i.name
              ),
            }));

            results.payment_fields = Array.from(
              document.querySelectorAll('[name*="card"], [id*="payment"]')
            ).map((p) => ({
              name: p.name || "",
              id: p.id || "",
            }));

            results.csrf_tokens = Array.from(
              document.querySelectorAll(
                'input[name*="_csrf"], input[name*="token"]'
              )
            ).map((t) => ({
              name: t.name || "",
              value: t.value || "",
            }));

            results.dynamic_scripts = Array.from(
              document.querySelectorAll("script")
            )
              .filter((s) => s.src && s.src.includes("?"))
              .map((s) => ({
                src: s.src,
              }));

            results.inline_styles = Array.from(
              document.querySelectorAll("[style]")
            ).map((e) => ({
              tag: e.tagName.toLowerCase(),
              style: e.getAttribute("style"),
            }));

            results.data_attributes = Array.from(document.querySelectorAll("*"))
              .filter(
                (e) =>
                  e.hasAttributes() &&
                  Array.from(e.attributes).some((a) =>
                    a.name.startsWith("data-")
                  )
              )
              .map((e) => ({
                tag: e.tagName.toLowerCase(),
                data: Object.fromEntries(Object.entries(e.dataset)),
              }));

            // Example for additional business logic/stateful elements:
            results.user_profiles = Array.from(
              document.querySelectorAll(
                '[name*="user"], [id*="user"], [class*="user"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_settings = Array.from(
              document.querySelectorAll(
                '[name*="setting"], [id*="setting"], [class*="setting"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_roles = Array.from(
              document.querySelectorAll(
                '[name*="role"], [id*="role"], [class*="role"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_permissions = Array.from(
              document.querySelectorAll(
                '[name*="permission"], [id*="permission"], [class*="permission"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_sessions = Array.from(
              document.querySelectorAll(
                '[name*="session"], [id*="session"], [class*="session"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_activities = Array.from(
              document.querySelectorAll(
                '[name*="activity"], [id*="activity"], [class*="activity"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_notifications = Array.from(
              document.querySelectorAll(
                '[name*="notification"], [id*="notification"], [class*="notification"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_messages = Array.from(
              document.querySelectorAll(
                '[name*="message"], [id*="message"], [class*="message"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_inbox = Array.from(
              document.querySelectorAll(
                '[name*="inbox"], [id*="inbox"], [class*="inbox"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_outbox = Array.from(
              document.querySelectorAll(
                '[name*="outbox"], [id*="outbox"], [class*="outbox"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_contacts = Array.from(
              document.querySelectorAll(
                '[name*="contact"], [id*="contact"], [class*="contact"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_groups = Array.from(
              document.querySelectorAll(
                '[name*="group"], [id*="group"], [class*="group"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_teams = Array.from(
              document.querySelectorAll(
                '[name*="team"], [id*="team"], [class*="team"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_projects = Array.from(
              document.querySelectorAll(
                '[name*="project"], [id*="project"], [class*="project"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_tasks = Array.from(
              document.querySelectorAll(
                '[name*="task"], [id*="task"], [class*="task"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_calendar = Array.from(
              document.querySelectorAll(
                '[name*="calendar"], [id*="calendar"], [class*="calendar"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_events = Array.from(
              document.querySelectorAll(
                '[name*="event"], [id*="event"], [class*="event"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_files = Array.from(
              document.querySelectorAll(
                '[name*="file"], [id*="file"], [class*="file"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_uploads = Array.from(
              document.querySelectorAll(
                '[name*="upload"], [id*="upload"], [class*="upload"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_downloads = Array.from(
              document.querySelectorAll(
                '[name*="download"], [id*="download"], [class*="download"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_orders = Array.from(
              document.querySelectorAll(
                '[name*="order"], [id*="order"], [class*="order"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_cart = Array.from(
              document.querySelectorAll(
                '[name*="cart"], [id*="cart"], [class*="cart"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_checkout = Array.from(
              document.querySelectorAll(
                '[name*="checkout"], [id*="checkout"], [class*="checkout"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_payments = Array.from(
              document.querySelectorAll(
                '[name*="payment"], [id*="payment"], [class*="payment"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_invoices = Array.from(
              document.querySelectorAll(
                '[name*="invoice"], [id*="invoice"], [class*="invoice"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_subscriptions = Array.from(
              document.querySelectorAll(
                '[name*="subscription"], [id*="subscription"], [class*="subscription"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_billing = Array.from(
              document.querySelectorAll(
                '[name*="billing"], [id*="billing"], [class*="billing"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_addresses = Array.from(
              document.querySelectorAll(
                '[name*="address"], [id*="address"], [class*="address"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_reviews = Array.from(
              document.querySelectorAll(
                '[name*="review"], [id*="review"], [class*="review"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_ratings = Array.from(
              document.querySelectorAll(
                '[name*="rating"], [id*="rating"], [class*="rating"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_comments = Array.from(
              document.querySelectorAll(
                '[name*="comment"], [id*="comment"], [class*="comment"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_likes = Array.from(
              document.querySelectorAll(
                '[name*="like"], [id*="like"], [class*="like"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_favorites = Array.from(
              document.querySelectorAll(
                '[name*="favorite"], [id*="favorite"], [class*="favorite"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_bookmarks = Array.from(
              document.querySelectorAll(
                '[name*="bookmark"], [id*="bookmark"], [class*="bookmark"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_history = Array.from(
              document.querySelectorAll(
                '[name*="history"], [id*="history"], [class*="history"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_preferences = Array.from(
              document.querySelectorAll(
                '[name*="preference"], [id*="preference"], [class*="preference"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_security = Array.from(
              document.querySelectorAll(
                '[name*="security"], [id*="security"], [class*="security"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_2fa = Array.from(
              document.querySelectorAll(
                '[name*="2fa"], [id*="2fa"], [class*="2fa"], [name*="twofactor"], [id*="twofactor"], [class*="twofactor"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_tokens = Array.from(
              document.querySelectorAll(
                '[name*="token"], [id*="token"], [class*="token"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_api_keys = Array.from(
              document.querySelectorAll(
                '[name*="api"], [id*="api"], [class*="api"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_devices = Array.from(
              document.querySelectorAll(
                '[name*="device"], [id*="device"], [class*="device"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_locations = Array.from(
              document.querySelectorAll(
                '[name*="location"], [id*="location"], [class*="location"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_activity_logs = Array.from(
              document.querySelectorAll(
                '[name*="activity"], [id*="activity"], [class*="activity"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_audit_logs = Array.from(
              document.querySelectorAll(
                '[name*="audit"], [id*="audit"], [class*="audit"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_reports = Array.from(
              document.querySelectorAll(
                '[name*="report"], [id*="report"], [class*="report"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_feedback = Array.from(
              document.querySelectorAll(
                '[name*="feedback"], [id*="feedback"], [class*="feedback"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_support_tickets = Array.from(
              document.querySelectorAll(
                '[name*="ticket"], [id*="ticket"], [class*="ticket"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_announcements = Array.from(
              document.querySelectorAll(
                '[name*="announcement"], [id*="announcement"], [class*="announcement"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_alerts = Array.from(
              document.querySelectorAll(
                '[name*="alert"], [id*="alert"], [class*="alert"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_wishlist = Array.from(
              document.querySelectorAll(
                '[name*="wishlist"], [id*="wishlist"], [class*="wishlist"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_referrals = Array.from(
              document.querySelectorAll(
                '[name*="referral"], [id*="referral"], [class*="referral"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_affiliates = Array.from(
              document.querySelectorAll(
                '[name*="affiliate"], [id*="affiliate"], [class*="affiliate"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_rewards = Array.from(
              document.querySelectorAll(
                '[name*="reward"], [id*="reward"], [class*="reward"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_points = Array.from(
              document.querySelectorAll(
                '[name*="point"], [id*="point"], [class*="point"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_badges = Array.from(
              document.querySelectorAll(
                '[name*="badge"], [id*="badge"], [class*="badge"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            results.user_achievements = Array.from(
              document.querySelectorAll(
                '[name*="achievement"], [id*="achievement"], [class*="achievement"]'
              )
            ).map((e) => ({
              id: e.id || "",
              name: e.getAttribute("name") || "",
              class: e.className || "",
            }));

            try {
              results.data_attributes = Array.from(
                document.querySelectorAll("[data-]")
              ).map((e) => ({
                tag: e.tagName.toLowerCase(),
                data: Object.fromEntries(Object.entries(e.dataset)),
              }));
            } catch (e) {
              results.data_attributes = [];
              console.error("Data attributes scraping failed:", e);
            }

            console.log(
              `[*] Found ${results.forms.length} forms, ${results.inputs.length} inputs, ${results.event_listeners.length} event listeners`
            );
            return results;
          }, userFunctionalities);
          break;
        } catch (e) {
          await logError(
            `DOM scraping attempt ${attempt}/5 failed: ${e.message}`,
            { attempt }
          );
          if (attempt < 5) {
            await page.evaluate(
              () => new Promise((resolve) => setTimeout(resolve, 10000))
            );
            const resolvedUrl = await resolveUrl(url);
            await page.goto(url, { waitUntil: "load", timeout: 600000 });
          }
        }
      }

      try {
        const dyn = await page.evaluate(() =>
          Array.isArray(window.__dynamicEventListeners)
            ? window.__dynamicEventListeners
            : []
        );
        if (Array.isArray(dyn) && dyn.length) {
          domData.event_listeners = (domData.event_listeners || []).concat(dyn);
        }
      } catch (e) {
        await logError(
          `Failed to collect dynamic event listeners: ${e.message}`
        );
      }

      if (!domData.forms) {
        await logError("All DOM scraping attempts failed, using empty domData");
        domData = userFunctionalities.reduce(
          (acc, func) => ({ ...acc, [func]: [] }),
          {}
        );
      }

      const baseHost = (() => {
        try {
          return new URL(url).hostname;
        } catch {
          return null;
        }
      })();
      const normalizeAbs = (u) => {
        try {
          const abs = new URL(u, url);
          abs.hash = "";
          if (abs.search && abs.search.length > 1) {
            const params = Array.from(new URLSearchParams(abs.search));
            params.sort(([a], [b]) => (a > b ? 1 : a < b ? -1 : 0));
            abs.search = params.length
              ? "?" + params.map(([k, v]) => `${k}=${v}`).join("&")
              : "";
          }
          return abs.toString();
        } catch {
          return null;
        }
      };
      const crawledUrls = new Set([normalizeAbs(url)]);
      const normalizedLinks = Array.from(
        new Set(
          (domData.links || [])
            .map((l) => (l && l.href ? normalizeAbs(l.href) : null))
            .filter((u) => u && (!baseHost || new URL(u).hostname === baseHost))
        )
      );
      const linksToCrawl = normalizedLinks.slice(0, crawlDepth);
      for (const linkHref of linksToCrawl) {
        if (crawledUrls.has(linkHref)) continue;
        try {
          await waitForFrameStability(page);
          await page.goto(linkHref, {
            waitUntil: "networkidle2",
            timeout: 600000,
          });
          crawledUrls.add(linkHref);
          const subDomData = await page.evaluate((functionalities) => {
            const results = {};
            functionalities.forEach((func) => {
              results[func] = [];
            });
            results.forms = Array.from(
              document.querySelectorAll('form, [data-form], [role="form"]')
            ).map((f) => ({
              action: f.action || f.getAttribute("data-action") || "",
              method: f.method || f.getAttribute("data-method") || "GET",
              inputs: Array.from(
                f.querySelectorAll("input, textarea, select")
              ).map((i) => ({
                name: i.name || "",
                type: i.type || "text",
                id: i.id || "",
              })),
            }));
            results.inputs = Array.from(document.querySelectorAll("input")).map(
              (i) => ({
                name: i.name || "",
                type: i.type || "text",
                id: i.id || "",
                value: i.value || "",
                hidden: i.type === "hidden",
              })
            );
            return results;
          }, userFunctionalities);
          domData.forms.push(...subDomData.forms);
          domData.inputs.push(...subDomData.inputs);
          await new Promise((resolve) => setTimeout(resolve, delay * 1000));
        } catch (e) {
          await logError(`Error crawling ${linkHref}: ${e.message}`, {
            url: linkHref,
          });
        }
      }

      // Deduplicate all arrays and add summary statistics with stable keys
      const dedupedDomData = {};
      const summary = {};
      const keyers = {
        links: (x) => normalizeAbs(x.href) || x.href || "",
        forms: (x) => `${(x.method || "GET").toUpperCase()}:${x.action || ""}`,
        inputs: (x) => `${x.type || ""}:${x.name || ""}:${x.id || ""}`,
        event_listeners: (x) =>
          `${x.tag || x.target || ""}:${x.id || ""}:${
            x.type || (x.events || []).sort().join(",")
          }`,
        scripts: (x) =>
          x.src ? normalizeAbs(x.src) || x.src : `inline:${x.inline ? 1 : 0}`,
        iframes: (x) => normalizeAbs(x.src) || x.id || "",
        admin_routes: (x) => normalizeAbs(x) || x,
        api_calls: (x) => normalizeAbs(x) || x,
        rest_endpoints: (x) => normalizeAbs(x) || x,
      };
      for (const type of userFunctionalities) {
        const value = domData[type];
        if (Array.isArray(value)) {
          let arr = value;
          if (["admin_routes", "api_calls", "rest_endpoints"].includes(type)) {
            arr = value
              .map((v) =>
                typeof v === "string" ? v : v && v.href ? v.href : ""
              )
              .map((u) => normalizeAbs(u))
              .filter(
                (u) => u && (!baseHost || new URL(u).hostname === baseHost)
              );
          }
          const seen = new Set();
          const deduped = [];
          arr.forEach((item) => {
            const keyFn = keyers[type] || ((x) => JSON.stringify(x));
            const key = keyFn(item);
            if (!key || seen.has(key)) return;
            seen.add(key);
            if (type === "links" && baseHost) {
              try {
                if (new URL(key).hostname !== baseHost) return;
              } catch (e) {}
            }
            deduped.push(item);
          });
          dedupedDomData[type] = deduped;
          summary[type] = deduped.length;
        } else {
          dedupedDomData[type] = value;
          summary[type] = 0;
        }
      }
      const functionalities = userFunctionalities.map((type) => ({
        type,
        details: dedupedDomData[type],
        reflected: false,
        vulnerable: false,
        vuln_reason: "",
        sanitized: false,
        sanitization_method: "None",
        bypass_method: "None",
      }));
      const outputFile = path.join(outputDir, "enumerate.json");
      const meta = {
        base_url: url,
        origin_host: (() => {
          try {
            return new URL(url).hostname;
          } catch {
            return null;
          }
        })(),
      };
      await fs.writeFile(
        outputFile,
        JSON.stringify({ ...meta, summary, functionalities }, null, 2),
        "utf8"
      );
      console.log(`[*] Enumeration saved to ${outputFile}`);
    } else if (mode === "reflection") {
      // Reflection mode (unchanged, retained with minor error handling improvements)
      const reflectionData = [];
      const selectedFuncs = selections.map((s) => s.type || "");
      for (const func of selections) {
        if (
          [
            "forms",
            "inputs",
            "auth_fields",
            "search_fields",
            "hidden_inputs",
            "textareas",
            "file_inputs",
          ].includes(func.type)
        ) {
          for (const item of func.details || []) {
            if (item.name || item.id) {
              const testValue = `test${Math.random()
                .toString(36)
                .substring(7)}`;
              try {
                await page.evaluate(
                  (testValue, name, id) => {
                    const el = document.querySelector(
                      `[name="${name}"],[id="${id}"]`
                    );
                    if (el) el.value = testValue;
                  },
                  testValue,
                  item.name || "",
                  item.id || ""
                );

                const reflected = await page.evaluate((testValue) => {
                  const body =
                    document.body?.innerHTML.includes(testValue) || false;
                  const dom =
                    document.documentElement?.innerHTML.includes(testValue) ||
                    false;
                  return { body, dom };
                }, testValue);

                reflectionData.push({
                  type: func.type,
                  details: item,
                  reflected: reflected.body || reflected.dom,
                  scope:
                    reflected.body && reflected.dom
                      ? "both"
                      : reflected.body
                      ? "body"
                      : "dom",
                });
              } catch (e) {
                await logError(
                  `Reflection test error for ${func.type} (${
                    item.name || item.id || "unknown"
                  }): ${e.message}`,
                  { type: func.type, item }
                );
              }
            }
          }
        }
      }

      const outputFile = path.join(outputDir, "reflection.json");
      await fs.writeFile(
        outputFile,
        JSON.stringify(
          { reflection: reflectionData.filter((r) => r.reflected) },
          null,
          2
        ),
        "utf8"
      );
      console.log(`[*] Reflection saved to ${outputFile}`);
    } else if (mode === "sinks") {
      // Sinks mode (unchanged, retained with minor error handling improvements)
      const sinkData = [];
      const selectedFuncs = selections.map((s) => s.type || "");
      for (const func of selections) {
        if (
          [
            "forms",
            "inputs",
            "auth_fields",
            "search_fields",
            "hidden_inputs",
            "textareas",
            "file_inputs",
          ].includes(func.type)
        ) {
          for (const item of func.details || []) {
            if (item.name || item.id) {
              const testValue = `test${Math.random()
                .toString(36)
                .substring(7)}`;
              try {
                await page.evaluate(
                  (testValue, name, id) => {
                    const el = document.querySelector(
                      `[name="${name}"],[id="${id}"]`
                    );
                    if (el) el.value = testValue;
                  },
                  testValue,
                  item.name || "",
                  item.id || ""
                );

                const sinks = await page.evaluate(
                  (testValue, xssSinks) => {
                    const results = [];
                    xssSinks.forEach((sink) => {
                      if (
                        document.body?.innerHTML.includes(sink) &&
                        document.body?.innerHTML.includes(testValue)
                      ) {
                        results.push(sink);
                      }
                    });
                    return results;
                  },
                  testValue,
                  xssSinks
                );

                sinkData.push({
                  type: func.type,
                  details: item,
                  sink: sinks.length > 0,
                  sink_type: sinks.join(", "),
                });
              } catch (e) {
                await logError(
                  `Sink test error for ${func.type} (${
                    item.name || item.id || "unknown"
                  }): ${e.message}`,
                  { type: func.type, item }
                );
              }
            }
          }
        }
      }

      const outputFile = path.join(outputDir, "sinks.json");
      await fs.writeFile(
        outputFile,
        JSON.stringify({ sinks: sinkData.filter((s) => s.sink) }, null, 2),
        "utf8"
      );
      console.log(`[*] Sinks saved to ${outputFile}`);
    } else if (mode === "vulnerable") {
      // Vulnerable mode (unchanged, retained with minor error handling improvements)
      const vulnData = [];
      const selectedFuncs = selections.map((s) => s.type || "");
      for (const func of selections) {
        if (
          [
            "forms",
            "inputs",
            "auth_fields",
            "search_fields",
            "hidden_inputs",
            "textareas",
            "file_inputs",
          ].includes(func.type)
        ) {
          for (const item of func.details || []) {
            if (item.name || item.id) {
              const testValue = `test${Math.random()
                .toString(36)
                .substring(7)}<script>alert(1)</script>`;
              try {
                await page.evaluate(
                  (testValue, name, id) => {
                    const el = document.querySelector(
                      `[name="${name}"],[id="${id}"]`
                    );
                    if (el) el.value = testValue;
                  },
                  testValue,
                  item.name || "",
                  item.id || ""
                );

                const vuln = await page.evaluate((testValue) => {
                  const xss =
                    document.body?.innerHTML.includes(testValue) || false;
                  const sql =
                    (/['";]/.test(testValue) &&
                      document.body?.innerHTML.includes(testValue)) ||
                    false;
                  const csrf = !document.querySelector('input[name*="_csrf"]');
                  const redirect = document.location.href.includes(testValue);
                  return { xss, sql, csrf, redirect };
                }, testValue);

                const isVulnerable =
                  vuln.xss || vuln.sql || vuln.csrf || vuln.redirect;
                const reason = isVulnerable
                  ? vuln.xss
                    ? "XSS detected"
                    : vuln.sql
                    ? "SQL injection pattern detected"
                    : vuln.csrf
                    ? "Missing CSRF token"
                    : "Open redirect detected"
                  : "";

                vulnData.push({
                  type: func.type,
                  details: item,
                  vulnerable: isVulnerable,
                  vuln_reason: reason,
                });
              } catch (e) {
                await logError(
                  `Vuln test error for ${func.type} (${
                    item.name || item.id || "unknown"
                  }): ${e.message}`,
                  { type: func.type, item }
                );
              }
            }
          }
        }
      }

      const outputFile = path.join(outputDir, "vulnerable.json");
      await fs.writeFile(
        outputFile,
        JSON.stringify(
          { vulnerable: vulnData.filter((v) => v.vulnerable) },
          null,
          2
        ),
        "utf8"
      );
      console.log(`[*] Vulnerable saved to ${outputFile}`);
    } else if (mode === "sanitization") {
      // Sanitization mode (unchanged, retained with minor error handling improvements)
      const sanitizationData = [];
      const selectedFuncs = selections.map((s) => s.type || "");
      const chars = [
        "<",
        ">",
        '"',
        "'",
        ";",
        "&",
        "--",
        "-",
        "|",
        "(",
        ")",
        "`",
        ",",
        ":",
        "{",
        "}",
        "[",
        "]",
        "$",
        "*",
        "%",
        "#",
        "@",
        "!",
        "?",
        "/",
        "\\",
        "=",
        "+",
        "-",
        "_",
        "\u202E",
      ];
      for (const func of selections) {
        if (
          [
            "forms",
            "inputs",
            "auth_fields",
            "search_fields",
            "hidden_inputs",
            "textareas",
            "file_inputs",
          ].includes(func.type)
        ) {
          for (const item of func.details || []) {
            if (item.name || item.id) {
              let inputElement = null;
              try {
                inputElement =
                  (await page.querySelector(`[name="${item.name}"]`)) ||
                  (await page.querySelector(`[id="${item.id}"]`));
                console.log(
                  `[*] Testing sanitization in input: ${item.name || item.id}`
                );
              } catch (e) {
                await logError(
                  `Failed to query input for sanitization: ${e.message}`,
                  { item }
                );
              }

              if (!inputElement) {
                await page.evaluate(() => {
                  const input = document.createElement("input");
                  input.setAttribute("data-test", "synthetic");
                  document.body.appendChild(input);
                });
                inputElement = await page.querySelector(
                  'input[data-test="synthetic"]'
                );
              }

              for (const char of chars) {
                const testValue = `test${char}test`;
                try {
                  const sanitization = await page.evaluate(
                    (testValue, name, id) => {
                      const input = document.querySelector(
                        `[name="${name}"],[id="${id}"],[data-test="synthetic"]`
                      );
                      input.value = testValue;
                      const isAllowed =
                        document.body?.innerHTML.includes(testValue) || false;
                      const isSanitized = input.value !== testValue;
                      const sanitizedValue = input.value;
                      return { isAllowed, isSanitized, sanitizedValue };
                    },
                    testValue,
                    item.name || "",
                    item.id || ""
                  );

                  sanitizationData.push({
                    type: func.type,
                    details: item,
                    char,
                    sanitized: sanitization.isSanitized,
                    method: sanitization.isSanitized
                      ? sanitization.sanitizedValue.includes("&")
                        ? "HTML encoding"
                        : "Unknown"
                      : "None",
                    bypass_method: sanitization.isSanitized
                      ? "Double encoding"
                      : "Direct injection",
                  });
                } catch (e) {
                  await logError(
                    `Sanitization test error for ${char}: ${e.message}`,
                    { char, item }
                  );
                }
              }
            }
          }
        }
      }

      const outputFile = path.join(outputDir, "sanitization.json");
      await fs.writeFile(
        outputFile,
        JSON.stringify(
          { sanitization: sanitizationData.filter((s) => s.sanitized) },
          null,
          2
        ),
        "utf8"
      );
      console.log(`[*] Sanitization saved to ${outputFile}`);
    } else if (mode === "characters") {
      // Characters mode (unchanged, retained with minor error handling improvements)
      const charData = { chars: [] };
      const selectedFuncs = selections[0]?.map((s) => s.type || "") || [];
      const chars = selections[1] || ["<", ">", '"', "'", ";", "&", "\u202E"];
      for (const func of selections[0] || []) {
        if (
          [
            "forms",
            "inputs",
            "auth_fields",
            "search_fields",
            "hidden_inputs",
            "textareas",
            "file_inputs",
          ].includes(func.type)
        ) {
          for (const item of func.details || []) {
            if (item.name || item.id) {
              let inputElement = null;
              try {
                inputElement =
                  (await page.querySelector(`[name="${item.name}"]`)) ||
                  (await page.querySelector(`[id="${item.id}"]`));
                console.log(
                  `[@] Testing characters in input: ${item.name || item.id}`
                );
              } catch (e) {
                await logError(
                  `Failed to query input for character testing: ${e.message}`,
                  { item }
                );
              }

              if (!inputElement) {
                await page.evaluate(() => {
                  const input = document.createElement("input");
                  input.setAttribute("data-test", "synthetic");
                  document.body.appendChild(input);
                });
                inputElement = await page.querySelector(
                  'input[data-test="synthetic"]'
                );
              }

              for (const char of chars) {
                const testValue = `test${char}test`;
                try {
                  const result = await page.evaluate(
                    (testValue, name, id) => {
                      const input = document.querySelector(
                        `[name="${name}"],[id="${id}"],[data-test="synthetic"]`
                      );
                      input.value = testValue;
                      const isAllowed =
                        document.body?.innerHTML.includes(testValue) || false;
                      return { testValue, isAllowed };
                    },
                    testValue,
                    item.name || "",
                    item.id || ""
                  );

                  charData.chars.push({
                    type: func.type,
                    details: item,
                    char,
                    allowed: result.isAllowed,
                    vulnerable:
                      result.isAllowed &&
                      ["<", ">", "'", '"', ";", "\u202E"].includes(char)
                        ? result.testValue
                        : null,
                  });
                } catch (e) {
                  await logError(
                    `Character test error for ${char}: ${e.message}`,
                    { char, item }
                  );
                }
              }
            }
          }
        }
      }

      const outputFile = path.join(outputDir, "characters.json");
      await fs.writeFile(
        outputFile,
        JSON.stringify(
          { chars: charData.chars.filter((c) => c.allowed || c.vulnerable) },
          null,
          2
        ),
        "utf8"
      );
      console.log(`[*] Characters saved to ${outputFile}`);
    } else {
      await logError(`Unknown mode: ${mode}`);
      throw new Error(`Invalid mode: ${mode}`);
    }
  } catch (e) {
    await logError(`Fatal error in extractJsData: ${e.stack}`, { url, mode });
    throw e;
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch (e) {
        await logError(`Failed to close browser: ${e.message}`);
      }
    }
    await cleanupTemp();
  }
}

// Execute main function with error handling
extractJsData().catch(async (err) => {
  await logError(`Main error: ${err.message}`, { stack: err.stack });
  process.exit(1);
});
