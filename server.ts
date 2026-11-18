import express from 'express';

interface Rule {
  id: string;
  title: string;
  category: string;
  severity: 'warn' | 'danger';
  weight: number;
  patterns: RegExp[];
  detail: string;
}

interface Flag {
  id: string;
  title: string;
  category: string;
  severity: 'warn' | 'danger';
  points: number;
  detail: string;
  matchedTerms: string[];
}

interface Span {
  start: number;
  end: number;
  category: string;
  reason: string;
  severity: 'warn' | 'danger';
}

const MESSAGE_RULES: Rule[] = [
  {
    id: 'msg-otp',
    title: 'Verification Code / OTP Harvesting',
    category: 'Credential Theft',
    severity: 'danger',
    weight: 42,
    patterns: [
      /\b(otp|one[- ]time[- ]pass(?:word|code)|6[- ]digit(?:\s+code)?|4[- ]digit(?:\s+code)?|verification\s+code|security\s+code|pin\s+code|2fa\s+code|secret\s+code|passcode)\b/gi,
      /\b(forward|share|send|read\s+back|reply\s+with|give\s+me|tell\s+me)\s+(?:me\s+)?(?:the|your|that)?\s*(?:code|otp|pin|password)\b/gi,
    ],
    detail: 'Scammers steal accounts by tricking you into forwarding a real one-time code sent to your phone.',
  },
  {
    id: 'msg-urgency',
    title: 'Artificial Urgency & Fear Pressure',
    category: 'Urgency Trap',
    severity: 'warn',
    weight: 26,
    patterns: [
      /\b(urgent(?:ly)?|asap|immediately|right\s+now|today\s+only|expires?(?:\s+today|\s+soon)?|expiring|within\s+\d+\s+(?:hours?|hrs?|mins?|minutes?)|final\s+notice|last\s+warning|last\s+chance|action\s+required|suspended|blocked|locked|deactivated|frozen|terminated|restricted|compromised|unauthorized|unusual\s+activity|security\s+alert|fraud\s+alert|disconnected|legal\s+action|arrest|penalty|late\s+fee)\b/gi,
    ],
    detail: 'Urgent deadlines or account threats push you to act before checking if the sender is genuine.',
  },
  {
    id: 'msg-payment',
    title: 'Prize, Fee, Refund, or Payment Lure',
    category: 'Financial Lure',
    severity: 'danger',
    weight: 34,
    patterns: [
      /\b(won|winner|congratulations|prize|lottery|jackpot|reward|giveaway|free\s+(?:iphone|gift|money|cash)|claim\s+(?:now|your|here|prize|refund|reward)|customs\s+fee|handling\s+fee|delivery\s+fee|redelivery|unpaid|overdue|payment\s+failed|update\s+payment|tax\s+refund|unclaimed|gift\s+card|apple\s+card|google\s+play|bitcoin|crypto|usdt|ethereum|airdrop|guaranteed\s+return|double\s+your\s+money|work\s+from\s+home|part[- ]time\s+job|daily\s+income|instant\s+loan|loan\s+approved|send\s+money|wire\s+transfer|zelle|venmo|cashapp|upi|paytm)\b/gi,
      /\$\s?\d+(?:,\d{3})*(?:\.\d{2})?/g,
    ],
    detail: 'Unexpected prizes, small parcel fees, or quick-cash offers are used to steal card details or money.',
  },
  {
    id: 'msg-credentials',
    title: 'Personal or Banking Information Request',
    category: 'Data Harvesting',
    severity: 'danger',
    weight: 30,
    patterns: [
      /\b(verify\s+(?:your\s+)?(?:account|identity|details|kyc|card)|confirm\s+(?:your\s+)?(?:details|account|identity)|update\s+(?:your\s+)?(?:kyc|billing|payment|account|details)|kyc\s+(?:expired|pending|update)|pan\s+card|aadhaar|ssn|social\s+security|bank\s+details|bank\s+account|credit\s+card|debit\s+card|card\s+number|cvv|routing\s+number|reset\s+password|unlock\s+(?:your\s+)?account|sign\s+in|log\s*in)\b/gi,
    ],
    detail: 'Asking you to verify banking info, IDs, or passwords from a message is a classic phishing tactic.',
  },
  {
    id: 'msg-cta',
    title: 'Suspicious Call-to-Action or Redirect',
    category: 'Social Engineering',
    severity: 'warn',
    weight: 20,
    patterns: [
      /\b(click\s+(?:here|below|the\s+link|this\s+link|link)|tap\s+(?:here|the\s+link|below)|visit\s+(?:this|the)\s+link|follow\s+(?:this|the)\s+link|open\s+(?:the\s+)?link|reply\s+(?:yes|stop)|kindly|dear\s+(?:customer|user|member)|valued\s+customer|lost\s+my\s+phone|new\s+number|whatsapp\s+me|message\s+me\s+on\s+telegram)\b/gi,
    ],
    detail: 'Generic greetings, "click here" prompts, or "new number" excuses are common mass-phishing hooks.',
  },
  {
    id: 'msg-impersonation',
    title: 'Brand or Authority Impersonation',
    category: 'Impersonation',
    severity: 'warn',
    weight: 20,
    patterns: [
      /\b(usps|fedex|dhl|ups|royal\s+mail|irs|hmrc|income\s+tax|paypal|amazon|netflix|apple|microsoft|google|whatsapp|telegram|instagram|chase|wells\s+fargo|bank\s+of\s+america|citibank|hsbc|hdfc|icici|sbi|bank\s+alert|fraud\s+department|customs|electricity\s+board|police|hr\s+department)\b/gi,
    ],
    detail: 'Scammers name trusted banks, couriers, and government agencies to borrow credibility.',
  },
];

const ATTACHMENT_RULES: Rule[] = [
  {
    id: 'att-double-ext',
    title: 'Disguised Double File Extension',
    category: 'Executable Masquerade',
    severity: 'danger',
    weight: 55,
    patterns: [
      /\b[\w.-]+\.(?:pdf|docx?|xlsx?|jpg|png|txt|csv)\.(?:exe|scr|bat|cmd|vbs|js|ps1|msi|hta|lnk|pif)\b/gi,
    ],
    detail: 'A filename ending in ".pdf.exe" is an executable program disguised as a document.',
  },
  {
    id: 'att-exec',
    title: 'High-Risk Executable, Script, or Disk Image',
    category: 'Malware Vector',
    severity: 'danger',
    weight: 48,
    patterns: [
      /\b[\w.-]+\.(?:exe|msi|bat|cmd|ps1|vbs|vbe|js|jse|wsf|scr|hta|iso|img|lnk|apk|dll|reg)\b/gi,
    ],
    detail: 'Executables, scripts, shortcuts (.lnk), and disk images (.iso) can run code on your device.',
  },
  {
    id: 'att-macro',
    title: 'Macro-Enabled Office Document',
    category: 'Macro Payload',
    severity: 'danger',
    weight: 38,
    patterns: [
      /\b[\w.-]+\.(?:docm|xlsm|pptm|dotm|xltm)\b/gi,
      /\b(enable\s+(?:content|macros|editing))\b/gi,
    ],
    detail: 'Files ending in "m" (.docm, .xlsm) contain macro scripts that activate when you click Enable Content.',
  },
  {
    id: 'att-archive-pwd',
    title: 'Password-Protected Archive Bypass',
    category: 'Scanner Evasion',
    severity: 'danger',
    weight: 34,
    patterns: [
      /\b[\w.-]+\.(?:zip|rar|7z|cab|tar|gz|ace)\b/gi,
      /\b(password\s*[:=]?\s*\S+|pwd\s*[:=]\s*\S+|extract\s+and\s+open)\b/gi,
    ],
    detail: 'Password-locked archives prevent email antivirus scanners from checking what is inside.',
  },
  {
    id: 'att-html',
    title: 'HTML / SVG Attachment Phishing',
    category: 'Credential Trap',
    severity: 'warn',
    weight: 30,
    patterns: [/\b[\w.-]+\.(?:html?|svg)\b/gi],
    detail: 'An emailed .html file opens a local web page—often a fake login form.',
  },
  {
    id: 'att-lure',
    title: 'Urgent Financial, HR, or Legal Lure',
    category: 'Social Engineering',
    severity: 'warn',
    weight: 22,
    patterns: [
      /\b(overdue|invoice|remittance|wire\s+receipt|payroll|bonus|voicemail|subpoena|court|late\s+penalties|urgent|confidential|scanned\s+document)\b/gi,
    ],
    detail: 'Invoices, payroll notices, and missed voicemails use curiosity or urgency to get a click.',
  },
];

const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'rb.gy', 'cutt.ly', 'is.gd', 'ow.ly', 'shorturl.at', 'wa.me', 't.me'];
const RISKY_TLDS = ['xyz', 'top', 'click', 'loan', 'gq', 'tk', 'ml', 'work', 'support', 'icu', 'cam', 'buzz', 'rest', 'cfd', 'club', 'online', 'site', 'vip'];
const BRANDS = [
  { brand: 'paypal', legit: ['paypal.com'] },
  { brand: 'paypa1', legit: [] },
  { brand: 'chase', legit: ['chase.com'] },
  { brand: 'amazon', legit: ['amazon.com', 'amazon.co.uk', 'amazon.in'] },
  { brand: 'arnazon', legit: [] },
  { brand: 'apple', legit: ['apple.com', 'icloud.com'] },
  { brand: 'microsoft', legit: ['microsoft.com', 'live.com', 'office.com'] },
  { brand: 'micros0ft', legit: [] },
  { brand: 'netflix', legit: ['netflix.com'] },
  { brand: 'usps', legit: ['usps.com'] },
  { brand: 'fedex', legit: ['fedex.com'] },
  { brand: 'dhl', legit: ['dhl.com'] },
  { brand: 'whatsapp', legit: ['whatsapp.com', 'wa.me'] },
  { brand: 'google', legit: ['google.com', 'accounts.google.com'] },
];

function runRules(text: string, rules: Rule[], flags: Flag[], spans: Span[]): number {
  let score = 0;
  for (const rule of rules) {
    const matched = new Set<string>();
    for (const pattern of rule.patterns) {
      const rx = new RegExp(pattern.source, pattern.flags);
      let m: RegExpExecArray | null;
      while ((m = rx.exec(text)) !== null) {
        if (!m[0]) break;
        matched.add(m[0]);
        spans.push({ start: m.index, end: m.index + m[0].length, category: rule.category, reason: rule.title, severity: rule.severity });
      }
    }
    if (matched.size > 0) {
      const points = rule.weight + (matched.size >= 3 ? 6 : 0);
      score += points;
      flags.push({ id: rule.id, title: rule.title, category: rule.category, severity: rule.severity, points, detail: rule.detail, matchedTerms: Array.from(matched).slice(0, 6) });
    }
  }
  return score;
}

function checkUrl(rawUrl: string, start: number, flags: Flag[], spans: Span[]): number {
  let score = 0;
  let parsed: URL;
  try {
    parsed = new URL(/^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`);
  } catch {
    return 0;
  }

  const host = parsed.hostname.toLowerCase();
  const add = (id: string, title: string, category: string, detail: string, severity: 'warn' | 'danger', points: number, term: string) => {
    if (!flags.some((f) => f.id === id)) {
      score += points;
      flags.push({ id, title, category, detail, severity, points, matchedTerms: [term] });
    }
    if (start >= 0) {
      spans.push({ start, end: start + rawUrl.length, category, reason: title, severity });
    }
  };

  if (rawUrl.includes('@')) add('url-at', 'Deceptive "@" Credential Masking', 'URL Obfuscation', 'Everything before "@" is ignored—your browser goes to the domain after "@".', 'danger', 48, rawUrl);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add('url-ip', 'Raw IP Address Host', 'Suspicious Host', 'Official websites use registered domain names, not raw numeric IP addresses.', 'danger', 42, host);
  if (host.startsWith('xn--') || host.includes('.xn--')) add('url-xn', 'Punycode Lookalike Domain (xn--)', 'Lookalike Spoof', 'Uses foreign lookalike characters to mimic trusted brands.', 'danger', 44, host);
  if (SHORTENERS.some((d) => host === d || host.endsWith(`.${d}`))) add('url-short', 'URL Shortener Hiding Destination', 'Opaque Redirect', 'Shortened links hide the real destination website until after you click.', 'warn', 28, host);

  const tld = host.split('.').pop() || '';
  if (RISKY_TLDS.includes(tld)) add('url-tld', `High-Abuse Domain Extension (.${tld})`, 'Domain Reputation', `Disposable extensions like .${tld} are heavily used by throwaway scam sites.`, 'warn', 26, `.${tld}`);
  if (/^http:\/\//i.test(rawUrl)) {
    const sensitive = /(login|verify|bank|account|kyc|pay|auth|secure|update|track|claim)/i.test(rawUrl);
    add('url-http', sensitive ? 'Unencrypted HTTP on Sensitive Page' : 'Unencrypted HTTP Link', 'Missing Encryption', 'Official login and payment portals use encrypted HTTPS links.', sensitive ? 'danger' : 'warn', sensitive ? 28 : 16, 'http://');
  }

  for (const b of BRANDS) {
    if (host.includes(b.brand) && !b.legit.some((d) => host === d || host.endsWith(`.${d}`))) {
      add(`url-brand-${b.brand}`, `Lookalike Brand Spoofing ("${b.brand}")`, 'Domain Spoofing', `"${host}" mentions "${b.brand}" but is not an official ${b.brand} domain.`, 'danger', 44, host);
      break;
    }
  }

  if ((host.match(/-/g) || []).length >= 2 && !flags.some((f) => f.id.startsWith('url-brand-'))) {
    add('url-hyphens', 'Multiple Hyphens in Domain', 'Domain Structure', 'Phishing domains often string trusted words together with hyphens.', 'warn', 20, host);
  }
  if ((host.match(/\./g) || []).length >= 3 && !flags.some((f) => f.id.startsWith('url-brand-'))) {
    add('url-sub', 'Excessive Subdomains', 'Domain Structure', 'Long subdomain chains push the real domain off mobile screens.', 'warn', 20, host);
  }

  const pathMatch = `${parsed.pathname}${parsed.search}`.match(/(login|signin|verify|update-kyc|kyc|secure|auth|confirm|redelivery|claim|reward|gift|bonus|billing|wallet|password|reset)/i);
  if (pathMatch) add('url-path', 'Phishing Path Keywords', 'Suspicious Path', `Path "${parsed.pathname}" contains verification or reward keywords common in scam links.`, 'warn', 20, pathMatch[0]);

  return score;
}

function mergeSpans(spans: Span[]): Span[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  const out: Span[] = [];
  for (const s of sorted) {
    const prev = out[out.length - 1];
    if (!prev || s.start >= prev.end) out.push({ ...s });
    else if (s.end > prev.end && s.severity === 'danger' && prev.severity === 'warn') out[out.length - 1] = { ...s, start: prev.start };
  }
  return out;
}

function analyze(vector: 'messages' | 'urls' | 'attachments', rawInput: string) {
  const input = rawInput.trim();
  const flags: Flag[] = [];
  const spans: Span[] = [];
  let rawScore = 0;

  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"']+|(?:[a-z0-9-]+\.)+(?:com|net|org|xyz|top|click|info|io|co|tk|ml|gq|support|work|icu|club|online|site|vip)(?:\/[^\s<>"']*)?/gi;
  const seenUrls = new Set<string>();
  let um: RegExpExecArray | null;
  while ((um = urlRegex.exec(input)) !== null) {
    const candidate = um[0].replace(/[.,;!?)]+$/, '');
    if (!candidate.includes('.') || seenUrls.has(candidate)) continue;
    if (vector === 'attachments' && /\.(pdf|docx?|xlsx?|exe|scr|bat|zip|rar|html?|docm|xlsm)$/i.test(candidate) && !candidate.includes('/') && !/^https?:\/\//i.test(candidate)) continue;
    seenUrls.add(candidate);
    rawScore += checkUrl(candidate, um.index, flags, spans);
  }

  if (vector === 'messages') {
    rawScore += runRules(input, MESSAGE_RULES, flags, spans);
    if (seenUrls.size > 0 && flags.some((f) => f.id.startsWith('msg-'))) {
      rawScore += 14;
      flags.push({ id: 'msg-link-combo', title: 'Urgent or Financial Message Paired With a Link', category: 'Combined Pattern', severity: 'danger', points: 14, detail: 'Combining urgent or financial language with a clickable link is a strong phishing pattern.', matchedTerms: Array.from(seenUrls).slice(0, 2) });
    }
  } else if (vector === 'urls') {
    if (seenUrls.size === 0 && input) rawScore += checkUrl(input, 0, flags, spans);
    rawScore += runRules(input, MESSAGE_RULES.slice(1, 4), flags, spans);
  } else {
    rawScore += runRules(input, ATTACHMENT_RULES, flags, spans);
  }

  const riskScore = Math.min(100, rawScore);
  const riskLevel = riskScore >= 65 ? 'critical' : riskScore >= 38 ? 'high' : riskScore >= 18 ? 'caution' : 'low';
  const verdictTitle =
    riskLevel === 'critical' ? 'Critical Scam Indicators Detected' :
    riskLevel === 'high' ? 'High Risk — Likely Fraud / Phishing' :
    riskLevel === 'caution' ? 'Suspicious Signals — Verify Before Acting' :
    'Low Automated Risk — No Known Triggers Found';

  const matchedWords = Array.from(new Set(flags.flatMap((f) => f.matchedTerms))).slice(0, 10);
  const workingSummary = flags.length === 0
    ? 'Checked urgency, OTP requests, financial lures, credential harvesting, URL spoofing, and file extensions — 0 red flags matched (0 / 100). Stay cautious if someone asks for money or codes.'
    : `Due to words/patterns like ${matchedWords.slice(0, 5).map((w) => `"${w}"`).join(', ')}, this scored ${riskScore}/100 (${flags.map((f) => `+${f.points}`).join(' ')}${rawScore > 100 ? ', capped at 100' : ''}) and is suspected as potential fraud.`;

  const safeSteps =
    riskLevel === 'low'
      ? ['Verify the sender address or phone number against a saved contact.', 'Never share one-time verification codes or passwords.', 'If anything feels rushed or unusual, confirm via an official website or app.']
      : vector === 'messages'
      ? ['Do not tap links, download files, or reply (even replying "STOP" confirms your number is active).', 'Never forward a 6-digit verification code to anyone—even a friend.', 'Open the company app or official website manually instead of using the link, then block and report the sender.']
      : vector === 'urls'
      ? ['Do not open the link or enter any password, OTP, or card number.', 'Open a fresh browser tab and type the official website address yourself.', 'If a friend sent it, verify on a separate app that their account was not hacked.']
      : ['Do not open, extract, or double-click the attachment—especially if it asks for a password or to Enable Content.', 'Verify with the sender using a separate phone call or new email thread.', 'Delete the email and mark it as phishing.'];

  const followUps = vector === 'attachments'
    ? [
        { id: 'opened-file', label: 'I already opened the attachment', title: 'Device Containment Steps', steps: ['Disconnect from Wi-Fi / Ethernet immediately.', 'Run a full offline antivirus scan and inspect recently installed apps.', 'From a different clean device, change your email and banking passwords.'] },
        { id: 'shared-otp', label: 'I already shared a code or password', title: 'Immediate Account Recovery Steps', steps: ['Change your password immediately from a clean browser or official app.', 'Sign out of all active sessions in Security Settings.', 'Change any reused passwords and enable app-based 2FA.'] },
        { id: 'paid-money', label: 'I already paid or gave card details', title: 'Financial Containment Checklist', steps: ['Call the number on the back of your card right away to freeze and replace it.', 'Report the fraud so your bank can open a dispute.', 'Save screenshots of the message, link, and receipt.'] },
      ]
    : [
        { id: 'clicked-link', label: 'I already clicked the link', title: 'What To Do After Clicking a Suspicious Link', steps: ['If you closed the tab without typing anything or downloading a file, clear browser tabs and cache.', 'If you entered a password, card number, or OTP, change your password right away and freeze your card.', 'Check your Downloads folder to ensure nothing downloaded silently.'] },
        { id: 'shared-otp', label: 'I already shared a code or password', title: 'Immediate Account Recovery Steps', steps: ['Change your password immediately from a clean browser or official app.', 'Sign out of all active sessions in Security Settings.', 'Change any reused passwords and enable app-based 2FA.'] },
        { id: 'paid-money', label: 'I already paid or gave card details', title: 'Financial Containment Checklist', steps: ['Call the number on the back of your card right away to freeze and replace it.', 'Report the fraud so your bank can open a dispute.', 'Save screenshots of the message, link, and receipt.'] },
      ];

  return { vector, input, riskScore, riskLevel, verdictTitle, workingSummary, matchedWords, flags, spans: mergeSpans(spans), safeSteps, followUps };
}

async function startServer() {
  const app = express();
  const allowedOrigins = (process.env.FRONTEND_URL || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  if (process.env.NODE_ENV !== 'production') {
    allowedOrigins.push('http://localhost:5173', 'http://127.0.0.1:5173');
  }

  // Allow the deployed Vercel frontend to call this API.
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    }
    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }
    next();
  });

  app.use(express.json({ limit: '100kb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.post('/api/analyze', (req, res) => {
    const vector = typeof req.body?.vector === 'string' ? req.body.vector : '';
    const input = typeof req.body?.input === 'string' ? req.body.input : '';

    if (vector !== 'messages' && vector !== 'urls' && vector !== 'attachments') {
      res.status(400).json({ error: 'Invalid vector.' });
      return;
    }
    if (!input.trim()) {
      res.status(400).json({ error: 'Please paste text or a link to analyze.' });
      return;
    }

    res.json(analyze(vector, input));
  });

  const PORT = Number(process.env.PORT) || 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Scamurai API running on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
