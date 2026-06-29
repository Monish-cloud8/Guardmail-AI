const KNOWN_BRANDS = [
  'paypal.com',
  'google.com',
  'apple.com',
  'amazon.com',
  'microsoft.com',
  'chase.com',
  'wellsfargo.com',
  'bankofamerica.com',
  'irs.gov',
  'netflix.com',
  'instagram.com',
  'facebook.com',
  'twitter.com',
  'linkedin.com',
  'dropbox.com',
];

const TRUSTED_DOMAINS = [
  'google.com',
  'gmail.com',
  'microsoft.com',
  'apple.com',
  'amazon.com',
  'linkedin.com',
  'dropbox.com',
  'github.com',
  'costco.com',
  'paypal.com',
];

const KNOWN_URL_SHORTENERS = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'buff.ly',
  'is.gd',
  'cutt.ly',
  'tiny.cc',
  'rebrand.ly',
];

const RISKY_TLDS = ['ru', 'tk', 'xyz', 'click', 'top', 'work', 'zip', 'country', 'gq'];
const SUSPICIOUS_DOMAIN_KEYWORDS = ['verify', 'secure', 'login', 'update', 'account', 'billing', 'wallet', 'support', 'auth'];
const COMMON_PHISHING_PHRASES = ['act now', 'verify your account', 'account locked', 'unusual activity', 'click here', 'confirm now', 'payment failed', 'urgent action'];

const state = {
  emails: [],
  analyzed: {},
  selectedByTab: {
    all: null,
    suspicious: null,
  },
  selectedDetail: null,
  filter: 'all',
  inspectorTab: 'overview',
  searchQuery: '',
  nextPageToken: null,
  chatHistoryByEmail: {},
  copilotOpen: false,
};

let glyphInterval = null;

function byId(id) {
  return document.getElementById(id);
}

function currentTab() {
  return state.filter;
}

function currentSelectedId() {
  return state.selectedByTab[currentTab()] || null;
}

function setCurrentSelectedId(id) {
  state.selectedByTab[currentTab()] = id;
}

function clearSelectedId(tab = currentTab()) {
  state.selectedByTab[tab] = null;
}

function selectedEmailIdsForTab(tab) {
  if (tab === 'suspicious') {
    return new Set(getSuspiciousEmails().map((item) => item.id));
  }
  return new Set(state.emails.map((item) => item.id));
}

function syncEmptyPanel(message = 'Select an email to view its analysis.') {
  byId('panel-empty').querySelector('.detail-empty-copy').textContent = message;
  state.selectedDetail = null;
  setInspectorTab('overview');
  setPanelState('panel-empty');
  renderCopilot();
}

function escapeHtml(value) {
  const div = document.createElement('div');
  div.textContent = value ?? '';
  return div.innerHTML;
}

function initTheme() {
  const light = (localStorage.getItem('theme') || 'dark') === 'light';
  document.documentElement.classList.toggle('light-mode', light);
  document.body.classList.toggle('light-mode', light);

  document.querySelectorAll('#theme-toggle, [data-theme-toggle]').forEach((toggle) => {
    toggle.addEventListener('click', () => {
      const nextLight = !document.body.classList.contains('light-mode');
      document.documentElement.classList.toggle('light-mode', nextLight);
      document.body.classList.toggle('light-mode', nextLight);
      localStorage.setItem('theme', nextLight ? 'light' : 'dark');
    });
  });
}

function initSearchToggle() {
  const toggle = byId('mail-search-toggle');
  const row = byId('mail-search-row');
  const input = byId('search-input');
  if (!toggle || !row || !input) return;

  toggle.addEventListener('click', () => {
    const hidden = row.classList.toggle('hidden');
    if (!hidden) input.focus();
  });
}

function initAccountMenu() {
  const button = byId('account-menu-button');
  const menu = byId('account-menu');
  if (!button || !menu) return;

  button.addEventListener('click', () => {
    const open = menu.classList.toggle('hidden');
    button.setAttribute('aria-expanded', String(!open));
  });

  document.addEventListener('click', (event) => {
    if (!menu.contains(event.target) && !button.contains(event.target)) {
      menu.classList.add('hidden');
      button.setAttribute('aria-expanded', 'false');
    }
  });

  menu.querySelectorAll('[data-account-email]').forEach((item) => {
    item.addEventListener('click', async () => {
      const email = item.getAttribute('data-account-email');
      if (!email) return;
      try {
        const response = await fetch('/auth/switch-account', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Failed to switch account');
        window.location.reload();
      } catch (error) {
        alert(`Error: ${error.message}`);
      }
    });
  });
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));

  for (let i = 0; i <= a.length; i += 1) dp[i][0] = i;
  for (let j = 0; j <= b.length; j += 1) dp[0][j] = j;

  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }

  return dp[a.length][b.length];
}

function hasNonAsciiChars(domain) {
  for (let index = 0; index < domain.length; index += 1) {
    if (domain.charCodeAt(index) > 0x024f) return true;
  }
  return false;
}

function extractDomain(emailAddress) {
  if (!emailAddress || !emailAddress.includes('@')) return '';
  return emailAddress.split('@').pop().trim().toLowerCase();
}

function analyzeDomain(domain) {
  const signals = [];
  let spoofed = false;
  const normalized = (domain || '').toLowerCase();

  if (!normalized) {
    return { signals, spoofed };
  }

  if (hasNonAsciiChars(normalized)) {
    signals.push('Sender domain contains visually deceptive Unicode characters');
    spoofed = true;
  }

  for (const brand of KNOWN_BRANDS) {
    if (normalized === brand) continue;
    const distance = levenshtein(normalized, brand);
    if (distance === 1 || distance === 2) {
      signals.push(`Sender domain is a lookalike of ${brand} - possible impersonation attack`);
      spoofed = true;
    }
  }

  return { signals, spoofed };
}

function parseAuthResults(headers) {
  const raw = headers['Authentication-Results'] || headers['authentication-results'] || '';
  const result = { spf: 'NONE', dkim: 'NONE', dmarc: 'NONE' };

  ['spf', 'dkim', 'dmarc'].forEach((key) => {
    const match = raw.match(new RegExp(`${key}=(\\w+)`, 'i'));
    if (match) result[key] = match[1].toUpperCase();
  });

  return result;
}

function extractOriginatingIp(headers) {
  const received = headers.Received || headers.received;
  if (!received) return null;
  const match = received.match(/\[?(\d{1,3}(?:\.\d{1,3}){3})\]?/);
  return match ? match[1] : null;
}

function buildAuthFlags(headers) {
  const flags = [];
  const fromValue = headers.From || '';
  const fromDomain = extractDomain(fromValue.match(/<(.+?)>/)?.[1] || fromValue);

  [
    ['Reply-To', headers['Reply-To'] || headers['reply-to']],
    ['Return-Path', headers['Return-Path'] || headers['return-path']],
  ].forEach(([label, value]) => {
    if (!value) return;
    const domain = extractDomain(value.match(/<(.+?)>/)?.[1] || value);
    if (domain && fromDomain && domain !== fromDomain) {
      flags.push(`${label} domain (${domain}) differs from From domain (${fromDomain})`);
    }
  });

  const ip = extractOriginatingIp(headers);
  if (ip) flags.push(`Originating IP (first Received hop): ${ip}`);

  return flags;
}

function jaccardSimilarity(a, b) {
  const setA = new Set((a || '').toLowerCase().split(/\s+/).filter(Boolean));
  const setB = new Set((b || '').toLowerCase().split(/\s+/).filter(Boolean));
  if (!setA.size || !setB.size) return 0;

  let overlap = 0;
  setA.forEach((word) => {
    if (setB.has(word)) overlap += 1;
  });

  return overlap / new Set([...setA, ...setB]).size;
}

function baseSenderDomain(emailAddress) {
  const parts = extractDomain(emailAddress).split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : parts.join('.');
}

function detectCampaigns() {
  const analyzedEntries = Object.entries(state.analyzed)
    .map(([id, data]) => ({ id, data, email: state.emails.find((item) => item.id === id) }))
    .filter((entry) => entry.email);

  const clusters = [];
  const visited = new Set();

  for (let i = 0; i < analyzedEntries.length; i += 1) {
    const current = analyzedEntries[i];
    if (visited.has(current.id)) continue;

    const cluster = [current];
    for (let j = i + 1; j < analyzedEntries.length; j += 1) {
      const candidate = analyzedEntries[j];
      if (visited.has(candidate.id)) continue;

      const sameBaseDomain =
        baseSenderDomain(current.email.senderEmail) &&
        baseSenderDomain(current.email.senderEmail) === baseSenderDomain(candidate.email.senderEmail);

      if (sameBaseDomain || jaccardSimilarity(current.email.subject, candidate.email.subject) > 0.4) {
        cluster.push(candidate);
      }
    }

    if (cluster.length >= 2) {
      cluster.forEach((item) => visited.add(item.id));
      clusters.push(cluster);
    }
  }

  return clusters;
}

function renderCampaignBanner() {
  const banner = byId('campaign-banner');
  const text = byId('campaign-banner-text');
  const clusters = detectCampaigns();

  if (!clusters.length) {
    banner.classList.add('hidden');
    return;
  }

  const largest = clusters.reduce((winner, candidate) => (
    candidate.length > winner.length ? candidate : winner
  ), clusters[0]);

  banner.classList.remove('hidden');
  text.textContent = `${largest.length} related emails grouped together${clusters.length > 1 ? ` (${clusters.length} clusters total)` : ''}`;
}

function clsForRisk(riskLevel) {
  if (riskLevel === 'Scam Alert') return 'is-scam';
  if (riskLevel === 'Suspicious') return 'is-spam';
  if (riskLevel === 'Review') return 'is-high';
  return 'is-safe';
}

function colorForScore(score) {
  if (score >= 85) return 'var(--threat)';
  if (score >= 70) return 'var(--caution)';
  return 'var(--safe)';
}

function isSuspicious(email) {
  const riskLevel = state.analyzed[email.id]?.riskLevel || email.riskLevel;
  return riskLevel === 'Scam Alert' || riskLevel === 'Suspicious';
}

function getSuspiciousEmails() {
  return state.emails.filter(isSuspicious);
}

function setPanelState(panelId) {
  ['panel-empty', 'panel-scanning', 'panel-error', 'panel-results'].forEach((id) => {
    byId(id).classList.toggle('hidden', id !== panelId);
  });
}

function setOverlayVisibility(visible) {
  byId('scanning-overlay').classList.toggle('is-visible', visible);
}

function setOverlayProgress(percent) {
  byId('overlay-progress-bar').style.width = `${Math.max(0, Math.min(100, percent))}%`;
}

function setOverlayStage(title, subcopy) {
  byId('overlay-stage').textContent = title;
  byId('overlay-subcopy').textContent = subcopy;
}

function appendOverlayLog(message, subtle) {
  const line = document.createElement('div');
  line.className = `scanning-log-line${subtle ? ' is-subtle' : ''}`;
  line.textContent = message;
  byId('overlay-log').appendChild(line);
}

function resetOverlay(modeLabel) {
  byId('overlay-log').innerHTML = '';
  setOverlayProgress(10);
  setOverlayStage(
    modeLabel === 'search' ? 'Searching ThreatDecoder AI...' : 'Initializing ThreatDecoder AI...',
    modeLabel === 'search'
      ? 'Running Gmail query and preparing threat analysis.'
      : 'Preparing Gmail connection and local ML analysis for 20 inbox emails.'
  );
  appendOverlayLog('boot: guardmail-ui ready');
  appendOverlayLog('auth: Gmail session detected', true);
}

function renderStats() {
  const total = state.emails.length;
  const scamCount = state.emails.filter((item) => item.riskLevel === 'Scam Alert').length;
  const spamCount = state.emails.filter((item) => item.riskLevel === 'Suspicious').length;
  const reviewCount = state.emails.filter((item) => item.riskLevel === 'Review').length;
  const safeCount = state.emails.filter((item) => item.riskLevel === 'Safe').length;

  byId('stat-total').textContent = String(total);
  byId('stat-spoofed').textContent = String(scamCount);
  byId('stat-clusters').textContent = String(spamCount);
  byId('stat-risk').textContent = String(reviewCount);
  byId('stat-risk-bar').style.width = '0%';
  byId('pipeline-count').textContent = state.searchQuery
    ? `${total} search results loaded`
    : total <= 20
      ? 'Scanning your latest 20 inbox emails first.'
      : `${total} inbox emails scanned so far.`;
  byId('message-total').textContent = String(
    state.filter === 'suspicious'
      ? getSuspiciousEmails().length
      : (state.searchQuery ? total : Math.min(total, 20))
  );
  renderOverview(total, scamCount, spamCount, reviewCount, safeCount);
}

function renderTabs() {
  const suspiciousCount = getSuspiciousEmails().length;
  byId('tab-suspicious-count').textContent = String(suspiciousCount);
  byId('tab-suspicious').classList.toggle('is-active', state.filter === 'suspicious');
  byId('tab-all').classList.toggle('is-active', state.filter === 'all');
  byId('list-heading').textContent = state.filter === 'suspicious'
    ? 'Suspicious Emails'
    : 'Top 20 Inbox Emails';
  byId('message-total').textContent = String(
    state.filter === 'suspicious'
      ? suspiciousCount
      : (state.searchQuery ? state.emails.length : Math.min(state.emails.length, 20))
  );
  byId('pipeline-count').textContent = state.filter === 'suspicious'
    ? (state.searchQuery
      ? `${suspiciousCount} suspicious search results shown.`
      : state.emails.length <= 20
        ? 'Showing suspicious emails from your latest 20 inbox emails.'
        : `Showing suspicious emails from ${state.emails.length} scanned inbox emails.`)
    : (state.searchQuery
      ? `${state.emails.length} search results loaded`
      : state.emails.length <= 20
        ? 'Scanning your latest 20 inbox emails first.'
        : `${state.emails.length} inbox emails scanned so far.`);
  byId('delete-suspicious-btn').classList.toggle(
    'hidden',
    state.filter !== 'suspicious' || suspiciousCount === 0
  );
  renderLoadMoreButton();
}

function renderPipeline() {
  renderTabs();

  const list = byId('pipeline-list');
  const emails = state.filter === 'suspicious' ? getSuspiciousEmails() : state.emails;
  const visibleEmails = state.filter === 'suspicious'
    ? emails
    : state.searchQuery
      ? emails
      : emails.slice(0, 20);

  if (!visibleEmails.length) {
    let message = 'No emails found.';
    if (state.searchQuery && state.emails.length === 0) {
      message = 'No emails found for that search.';
    } else if (state.filter === 'suspicious') {
      message = 'No suspicious emails found.';
    }

    list.innerHTML = `<div class="list-placeholder">${escapeHtml(message)}</div>`;
    return;
  }

  list.innerHTML = '';
  visibleEmails.forEach((email, index) => {
    const cached = state.analyzed[email.id] || {};
    const riskLevel = cached.riskLevel || email.riskLevel || 'Safe';
    const riskScore = cached.riskScore ?? email.riskScore ?? 0;
    const sender = email.senderName || email.senderEmail || 'Unknown sender';
    const primaryReason = riskLevel === 'Safe' ? '' : ((cached.reasons || email.reasons || [])[0] || '');
    const row = document.createElement('article');
    const dotClass = riskLevel === 'Scam Alert'
      ? 'status-threat'
      : riskLevel === 'Suspicious'
        ? 'status-spam'
        : riskLevel === 'Review'
          ? 'status-high'
          : 'status-safe';

    row.className = `email-row${currentSelectedId() === email.id ? ' is-selected' : ''}${email.unread ? ' is-unread' : ''}`;
    row.style.animationDelay = `${index * 30}ms`;
    row.innerHTML = `
      <div class="email-row-left">
        <span class="status-dot ${dotClass}"></span>
        <div style="min-width:0">
          <div class="email-sender">${escapeHtml(sender)}${email.senderEmail ? `<span class="email-address-inline">${escapeHtml(email.senderEmail)}</span>` : ''}</div>
          <div class="email-subject">${escapeHtml(email.subject || '(No subject)')}</div>
          <div class="email-preview">${escapeHtml(email.preview || '')}</div>
          ${primaryReason ? `<div class="email-reason">${escapeHtml(primaryReason)}</div>` : ''}
        </div>
      </div>
      <div class="email-meta">
        <span class="threat-badge ${clsForRisk(riskLevel)} mono">${escapeHtml(riskLevel)}</span>
        <div class="email-score mono">${escapeHtml(String(riskScore))}%</div>
        <div class="email-time">${escapeHtml(email.timestamp || '')}</div>
      </div>
    `;

    row.addEventListener('click', () => selectEmail(email.id));
    list.appendChild(row);
  });
}

function renderConfidenceBar(container, label, value) {
  const normalized = Math.max(0, Math.min(100, Number(value) || 0));
  const row = document.createElement('div');
  row.className = 'confidence-row';
  row.innerHTML = `
    <header>
      <span>${escapeHtml(label)}</span>
      <span class="mono">${normalized}%</span>
    </header>
    <div class="confidence-bar">
      <span style="width:${normalized}%; background:${colorForScore(normalized)}"></span>
    </div>
  `;
  container.appendChild(row);
}

function detailBullet(text, warning) {
  return `
    <div class="detail-bullet">
      ${warning ? '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>' : '<span style="width:15px; display:block"></span>'}
      <span>${escapeHtml(text)}</span>
    </div>
  `;
}

function setInspectorTab(tab) {
  state.inspectorTab = tab;
  ['overview', 'investigation', 'intel'].forEach((key) => {
    const tabButton = byId(`inspector-tab-${key}`);
    const section = byId(`inspector-section-${key}`);
    if (tabButton) tabButton.classList.toggle('is-active', key === tab);
    if (section) section.classList.toggle('hidden', key !== tab);
  });
}

function levelFromScore(score) {
  if (score >= 80) return 'High Risk';
  if (score >= 55) return 'Suspicious';
  if (score >= 30) return 'Unknown';
  return 'Good';
}

function normalizedUrlDomain(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (error) {
    return '';
  }
}

function senderDomain(detail) {
  return extractDomain(detail.senderEmail || '');
}

function phishingPhraseHits(detail) {
  const text = `${detail.subject || ''} ${detail.body || ''}`.toLowerCase();
  return COMMON_PHISHING_PHRASES.filter((phrase) => text.includes(phrase));
}

function recommendationForRisk(riskLevel) {
  if (riskLevel === 'Scam Alert') return 'Do not click links. Review carefully or move to trash.';
  if (riskLevel === 'Suspicious') return 'Avoid interacting with links or attachments until you verify the sender.';
  if (riskLevel === 'Review') return 'Pause before acting and verify the sender or request through another channel.';
  return 'Looks safe from the current local checks, but keep normal email caution.';
}

function generateThreatInvestigation(detail) {
  const riskLevel = detail.riskLevel || 'Safe';
  const confidence = detail.confidenceScore ?? detail.riskScore ?? 0;
  const reasons = [];
  const linkSummary = detail.detectedLinksSummary || {};
  const auth = detail.authChain || {};
  const domain = senderDomain(detail);
  const linkDomains = (detail.links || []).map((link) => link.domain).filter(Boolean);
  const phrases = phishingPhraseHits(detail);

  if ((detail.reasons || []).includes('Sender mismatch') || detail.domainSignals?.length) reasons.push('sender domain mismatch');
  if ((linkSummary.suspiciousDomains || 0) > 0 || (linkSummary.shortened || 0) > 0) reasons.push('suspicious or shortened links');
  if ((detail.reasons || []).includes('Urgent language') || phrases.length) reasons.push('urgent language');
  if ((detail.attachmentWarnings || []).length) reasons.push('risky attachment type');
  if (auth.spf === 'FAIL' || auth.dkim === 'FAIL' || auth.dmarc === 'FAIL') reasons.push('failed email authentication');
  if (detail.senderStatus === 'blocked') reasons.push('sender is blocked');
  if (detail.senderStatus !== 'safe' && riskLevel !== 'Safe') reasons.push('sender is not trusted');
  if (confidence >= 90) reasons.push('model confidence is high');
  if ((linkSummary.displayMismatch || 0) > 0) reasons.push('link display text does not match the real URL');
  if (phrases.length) reasons.push(`common phishing phrase${phrases.length > 1 ? 's' : ''}: ${phrases.slice(0, 2).join(', ')}`);
  if (!reasons.length && riskLevel === 'Safe') reasons.push('no major local warning signals');

  const explanation = riskLevel === 'Safe'
    ? `Overall Risk: ${riskLevel} (${confidence}%). This email looks okay based on the current local checks and did not trigger strong fraud signals.`
    : `Overall Risk: ${riskLevel} (${confidence}%). This email looks risky because it shows ${reasons.slice(0, 3).join(', ')}.`;

  const mismatchedLinks = linkDomains.filter((linkDomain) => linkDomain && domain && linkDomain !== domain);

  return {
    overallRisk: riskLevel,
    confidence,
    explanation,
    recommendation: recommendationForRisk(riskLevel),
    points: [
      ...reasons,
      ...(mismatchedLinks.length ? [`sender and link domains differ (${domain} vs ${mismatchedLinks[0]})`] : []),
    ],
  };
}

function scoreDomainLocally(domain, detail) {
  if (!domain) return { score: 50, level: 'Unknown', signals: ['no sender domain available'] };
  let score = 18;
  const signals = [];

  if (TRUSTED_DOMAINS.includes(domain)) score -= 12;
  if (detail.senderStatus === 'safe') score -= 18;
  if (detail.senderStatus === 'blocked') {
    score += 45;
    signals.push('local blocklist match');
  }
  if (RISKY_TLDS.includes(domain.split('.').pop())) {
    score += 18;
    signals.push('risky top-level domain');
  }
  if (SUSPICIOUS_DOMAIN_KEYWORDS.some((keyword) => domain.includes(keyword))) {
    score += 16;
    signals.push('suspicious keyword in domain');
  }
  if (detail.domainSignals?.length) {
    score += 24;
    signals.push('lookalike or spoof-style sender domain');
  }
  if (detail.authChain?.spf === 'FAIL' || detail.authChain?.dkim === 'FAIL' || detail.authChain?.dmarc === 'FAIL') {
    score += 20;
    signals.push('failed authentication');
  }

  score = Math.max(0, Math.min(100, score));
  return { score, level: levelFromScore(score), signals };
}

function scoreLinksLocally(links, detail) {
  if (!links?.length) return { score: 8, level: 'Good', signals: ['no links found'] };
  let score = 12;
  const signals = [];
  const sender = senderDomain(detail);

  links.forEach((link) => {
    if (link.usesShortener) {
      score += 18;
      signals.push('URL shortener used');
    }
    if (link.displayDomainDiffers) {
      score += 22;
      signals.push('display text differs from destination');
    }
    if (link.looksSuspicious) {
      score += 20;
      signals.push('link domain looks suspicious');
    }
    if (link.domain && sender && link.domain !== sender) {
      score += 12;
      signals.push('link domain differs from sender');
    }
    if (RISKY_TLDS.includes((link.domain || '').split('.').pop())) {
      score += 14;
      signals.push('link uses risky TLD');
    }
  });

  score = Math.max(0, Math.min(100, score));
  return { score, level: levelFromScore(score), signals: [...new Set(signals)] };
}

function scoreAttachmentsLocally(attachments) {
  if (!attachments?.length) return { score: 6, level: 'Good', signals: ['no risky attachments detected'] };
  const score = Math.min(100, 50 + (attachments.length * 12));
  return {
    score,
    level: score >= 55 ? 'Suspicious' : 'Unknown',
    signals: attachments.map((item) => `${item.filename} (${item.extension || 'flagged'})`),
  };
}

function analyzeLocalThreatIntel(detail) {
  const domainIntel = scoreDomainLocally(senderDomain(detail), detail);
  const linkIntel = scoreLinksLocally(detail.links || [], detail);
  const attachmentIntel = scoreAttachmentsLocally(detail.attachmentWarnings || []);
  const safelistMatch = detail.senderStatus === 'safe';
  const blocklistMatch = detail.senderStatus === 'blocked';
  const finalScore = Math.round((domainIntel.score * 0.45) + (linkIntel.score * 0.35) + (attachmentIntel.score * 0.2));

  return {
    senderDomainReputation: domainIntel.level,
    linkReputation: linkIntel.level,
    attachmentReputation: attachmentIntel.level,
    localBlocklistMatch: blocklistMatch ? 'Yes' : 'No',
    localSafelistMatch: safelistMatch ? 'Yes' : 'No',
    finalThreatIntelScore: finalScore,
    details: {
      domain: domainIntel.signals,
      links: linkIntel.signals,
      attachments: attachmentIntel.signals,
    },
  };
}

function answerEmailQuestion(question, detail) {
  const q = (question || '').trim().toLowerCase();
  const investigation = generateThreatInvestigation(detail);
  const threatIntel = analyzeLocalThreatIntel(detail);
  const reasons = detail.reasons || [];
  const links = detail.links || [];
  const attachments = detail.attachmentWarnings || [];

  if (!q) {
    return 'Ask about why this email was flagged, whether it looks safe, risky links, attachments, or what action to take.';
  }
  if (q.includes('12') || q.includes('simple')) {
    return detail.riskLevel === 'Safe'
      ? 'This one looks okay. I did not find strong warning signs in the sender, links, or attachments.'
      : `This email might be trying to trick you. The main warnings are: ${(reasons.slice(0, 2).join(', ') || 'suspicious patterns')}.`;
  }
  if (q.includes('why') || q.includes('suspicious')) {
    return reasons.length
      ? `It was flagged because of: ${reasons.join(', ')}. ${investigation.recommendation}`
      : investigation.explanation;
  }
  if (q.includes('trust') || q.includes('safe')) {
    return detail.riskLevel === 'Safe'
      ? 'This currently looks safe from the app’s local checks, but still use normal caution.'
      : `I would be careful. Risk level is ${detail.riskLevel} at ${investigation.confidence}% confidence. ${investigation.recommendation}`;
  }
  if (q.includes('link')) {
    return links.length
      ? `Risky link summary: ${links.map((link) => `${link.domain || 'unknown domain'}${link.usesShortener ? ' (shortener)' : ''}${link.displayDomainDiffers ? ' (display mismatch)' : ''}`).join('; ')}.`
      : 'There are no links extracted from this email.';
  }
  if (q.includes('attachment')) {
    return attachments.length
      ? `Attachment warnings: ${attachments.map((item) => item.filename).join(', ')}.`
      : 'No risky attachments were detected.';
  }
  if (q.includes('do') || q.includes('action') || q.includes('should i')) {
    return investigation.recommendation;
  }
  if (q.includes('confidence')) {
    return `The confidence score is ${investigation.confidence}%. In this app, that means how strongly the local model and rules agree with the final risk label.`;
  }

  return 'I can answer questions about why this email was flagged, whether it looks safe, risky links, attachments, or what action to take.';
}

function renderThreatInvestigation(detail) {
  const investigation = generateThreatInvestigation(detail);
  const steps = [
    ['Sender analyzed', senderDomain(detail) || 'sender unavailable'],
    ['Domain checked', detail.domainSignals?.[0] || 'no spoof-style mismatch found'],
    ['Links extracted', (detail.links || []).length ? `${detail.links.length} link(s) reviewed` : 'no links found'],
    ['Language analyzed', (detail.reasons || []).includes('Urgent language') ? 'urgent language detected' : 'no strong urgency pattern'],
    ['Attachments scanned', (detail.attachmentWarnings || []).length ? `${detail.attachmentWarnings.length} warning(s)` : 'no risky attachments'],
    ['Confidence calculated', `${investigation.confidence}% confidence`],
  ];

  byId('res-investigation-summary').innerHTML = `
    <div class="investigation-hero">
      <div>
        <div class="inspector-title">Investigation Result</div>
        <div class="investigation-copy">${escapeHtml(investigation.explanation)}</div>
      </div>
      <strong class="threat-badge ${clsForRisk(investigation.overallRisk)} mono">${escapeHtml(investigation.overallRisk)}</strong>
    </div>
    <div class="investigation-metrics">
      <div class="investigation-metric">
        <span>Confidence</span>
        <strong class="mono">${investigation.confidence}%</strong>
      </div>
      <div class="investigation-metric">
        <span>Recommendation</span>
        <strong>${escapeHtml(investigation.recommendation)}</strong>
      </div>
    </div>
  `;
  byId('res-investigation-points').innerHTML = `
    <div class="investigation-timeline">
      ${steps.map(([label, copy]) => `
        <div class="timeline-step">
          <span class="timeline-dot">✓</span>
          <div>
            <strong>${escapeHtml(label)}</strong>
            <div>${escapeHtml(copy)}</div>
          </div>
        </div>
      `).join('')}
    </div>
    <div class="investigation-recommendation">${escapeHtml(investigation.recommendation)}</div>
    ${investigation.points.length
      ? `<div class="investigation-notes">${investigation.points.map((item) => detailBullet(item, true)).join('')}</div>`
      : '<div class="detail-status-safe">No major warning signals were found.</div>'}
  `;
}

function renderThreatIntel(detail) {
  const intel = analyzeLocalThreatIntel(detail);
  const rows = [
    ['Sender Domain Reputation', intel.senderDomainReputation],
    ['Link Reputation', intel.linkReputation],
    ['Attachment Reputation', intel.attachmentReputation],
    ['Local Blocklist Match', intel.localBlocklistMatch],
    ['Local Safelist Match', intel.localSafelistMatch],
    ['Final Threat Intel Score', `${intel.finalThreatIntelScore}/100`],
  ];

  byId('res-threat-intel').innerHTML = `
    <div class="intel-grid">
      ${rows.map(([label, value]) => `
        <div class="intel-card">
          <span class="intel-label">${escapeHtml(label)}</span>
          <div class="intel-summary-row">
            <strong>${escapeHtml(value)}</strong>
            <span class="intel-status-dot ${clsForRisk(detail.riskLevel || 'Safe')}"></span>
          </div>
        </div>
      `).join('')}
    </div>
    <div class="intel-detail-block">
      <div class="inspector-title">Domain Signals</div>
      ${intel.details.domain.map((item) => detailBullet(item, false)).join('') || '<div class="detail-link">No notable sender-domain warnings.</div>'}
    </div>
    <div class="intel-detail-block">
      <div class="inspector-title">Link Signals</div>
      ${intel.details.links.map((item) => detailBullet(item, false)).join('') || '<div class="detail-link">No notable link warnings.</div>'}
    </div>
    <div class="intel-detail-block">
      <div class="inspector-title">Attachment Signals</div>
      ${intel.details.attachments.map((item) => detailBullet(item, false)).join('') || '<div class="detail-link">No notable attachment warnings.</div>'}
    </div>
  `;
}

function renderChat(detail) {
  renderCopilot(detail);
}

function assistantContextKey(detail = state.selectedDetail) {
  return detail?.id || '__app__';
}

function assistantContext(detail = state.selectedDetail) {
  return {
    selectedEmail: detail || null,
    currentTab: currentTab(),
    emailCount: state.emails.length,
    suspiciousCount: getSuspiciousEmails().length,
  };
}

function copilotSuggestions(detail = state.selectedDetail) {
  if (detail) {
    return [
      'Why is this suspicious?',
      'What links are dangerous?',
      'What should I do?',
    ];
  }
  return [
    'How do I scan my inbox?',
    'What does Scam Alert mean?',
    'How does this application detect scams?',
  ];
}

function setCopilotOpen(open) {
  state.copilotOpen = open;
  byId('copilot-panel').classList.toggle('hidden', !open);
  byId('copilot-shell').classList.toggle('is-open', open);
  byId('copilot-toggle').setAttribute('aria-expanded', String(open));
  if (open) {
    byId('copilot-input').focus();
  }
}

function renderCopilot(detail = state.selectedDetail) {
  const context = assistantContext(detail);
  const key = assistantContextKey(detail);
  const history = state.chatHistoryByEmail[key] || [];
  const contextLabel = detail
    ? `Focused on ${detail.subject || '(No subject)'}`
    : 'Ask about this app or the selected email.';
  const intro = detail
    ? 'Ask why it was flagged, whether the links are risky, or what action to take.'
    : 'Ask how scanning works, what the risk levels mean, or how to manage suspicious emails.';

  byId('copilot-context').textContent = contextLabel;
  byId('copilot-suggestions').innerHTML = copilotSuggestions(detail)
    .map((question) => `<button class="copilot-suggestion" type="button" data-copilot-question="${escapeHtml(question)}">${escapeHtml(question)}</button>`)
    .join('');
  byId('copilot-log').innerHTML = history.length
    ? history.map((item) => `
      <div class="chat-message chat-message-${item.role}">
        <strong>${item.role === 'user' ? 'You' : 'Security Copilot'}</strong>
        <div>${escapeHtml(item.text)}</div>
      </div>
    `).join('')
    : `<div class="detail-link">${escapeHtml(intro)}</div>`;

  byId('copilot-shell').querySelectorAll('[data-copilot-question]').forEach((button) => {
    button.addEventListener('click', () => submitCopilotQuestion(button.getAttribute('data-copilot-question') || ''));
  });

  const log = byId('copilot-log');
  log.scrollTop = log.scrollHeight;
  return context;
}

function submitCopilotQuestion(question) {
  const cleanQuestion = String(question || '').trim();
  if (!cleanQuestion || !window.GuardMailAssistant) return;

  const detail = state.selectedDetail;
  const key = assistantContextKey(detail);
  const history = state.chatHistoryByEmail[key] || [];
  history.push({ role: 'user', text: cleanQuestion });
  history.push({
    role: 'assistant',
    text: window.GuardMailAssistant.answerQuestion(cleanQuestion, assistantContext(detail)),
  });
  state.chatHistoryByEmail[key] = history.slice(-10);
  byId('copilot-input').value = '';
  setCopilotOpen(true);
  renderCopilot(detail);
}

function renderResults(email, detail) {
  const analysis = detail.analysis || {};
  const riskScore = detail.riskScore ?? analysis.riskScore ?? 0;
  const riskLevel = detail.riskLevel || analysis.riskLevel || 'Safe';
  const isSafe = riskLevel === 'Safe';

  byId('res-sender').textContent = email.senderName || email.senderEmail || 'Unknown sender';
  byId('res-subject').textContent = `${email.senderEmail || ''} | ${email.timestamp || ''}`;
  byId('res-body').textContent = detail.body || email.preview || '';
  byId('res-risk').textContent = `${riskScore}%`;
  byId('res-gauge').style.setProperty('--risk-pct', `${riskScore}%`);
  byId('res-gauge').style.setProperty('--risk-color', colorForScore(riskScore));
  byId('res-gauge-value').textContent = `${riskScore}%`;

  const badge = byId('res-badge');
  badge.className = `threat-badge ${clsForRisk(riskLevel)} mono`;
  badge.textContent = riskLevel;

  const tacticTag = byId('res-tactic-tag');
  const tacticExplanation = byId('res-tactic-explanation');
  if (analysis.socialEngineeringTactic && analysis.socialEngineeringTactic !== 'NONE') {
    tacticTag.className = 'threat-badge is-high mono';
    tacticTag.textContent = analysis.socialEngineeringTactic.replace(/_/g, ' ');
    tacticTag.classList.remove('hidden');
    tacticExplanation.textContent = analysis.tacticExplanation || '';
    tacticExplanation.classList.remove('hidden');
  } else {
    tacticTag.classList.add('hidden');
    tacticExplanation.classList.add('hidden');
  }

  const whyFlagged = [...(analysis.whyFlagged || [])];
  if (detail.domainSignals?.length) {
    whyFlagged.push(...detail.domainSignals);
  }

  byId('res-why-flagged-section').classList.toggle('hidden', whyFlagged.length === 0);
  byId('res-why-flagged').innerHTML = whyFlagged.map((item) => detailBullet(item, true)).join('');

  const reasonsCardTitle = byId('res-reasons-title');
  const reasons = isSafe ? [] : (detail.reasons || analysis.reasons || []);
  reasonsCardTitle.textContent = isSafe ? 'Status' : 'Fraud Reasons';
  byId('res-reasons').innerHTML = isSafe
    ? '<div class="detail-status-safe">No fraud indicators found.</div>'
    : reasons.length
      ? reasons.map((item) => detailBullet(item, true)).join('')
      : '<div class="list-placeholder" style="padding:0; text-align:left">No fraud reasons reported.</div>';

  const allSignals = [...(analysis.signalAnalysis || []), ...(detail.domainSignals || []), ...(detail.authFlags || [])];
  byId('res-signals').innerHTML = allSignals.length
    ? allSignals.map((item) => detailBullet(item, false)).join('')
    : '<div class="list-placeholder" style="padding:0; text-align:left">No signals reported.</div>';

  const confidence = byId('res-confidence');
  confidence.innerHTML = '';
  const breakdown = analysis.confidenceBreakdown || {};
  renderConfidenceBar(confidence, 'Urgency Language', breakdown.urgencyLanguage ?? 0);
  renderConfidenceBar(confidence, 'Domain Mismatch', breakdown.domainMismatch ?? 0);
  renderConfidenceBar(confidence, 'Header Anomalies', breakdown.headerAnomalies ?? 0);
  renderConfidenceBar(confidence, 'Link Patterns', breakdown.linkPatterns ?? 0);
  renderConfidenceBar(confidence, 'Sender Reputation', breakdown.senderReputation ?? 0);

  const auth = byId('res-auth');
  auth.innerHTML = '';
  [
    ['SPF', detail.authChain.spf],
    ['DKIM', detail.authChain.dkim],
    ['DMARC', detail.authChain.dmarc],
  ].forEach(([label, value]) => {
    const color =
      value === 'PASS'
        ? 'var(--safe)'
        : value === 'FAIL'
          ? 'var(--threat)'
          : 'var(--muted)';

    const box = document.createElement('div');
    box.className = 'auth-box';
    box.innerHTML = `
      <div class="mono" style="color:var(--muted-2); font-size:11px;">${label}</div>
      <strong class="mono" style="color:${color}">${value}</strong>
    `;
    auth.appendChild(box);
  });

  byId('res-auth-flags').innerHTML = (detail.authFlags || [])
    .map((flag) => `<div class="detail-flag">${escapeHtml(flag)}</div>`)
    .join('');

  byId('res-headers').innerHTML = ['From', 'Reply-To', 'Return-Path']
    .map((header) => {
      const value = (detail.headers || {})[header];
      if (!value) return '';
      return `<div class="detail-header"><strong>${header}</strong><br>${escapeHtml(value)}</div>`;
    })
    .join('');

  const links = detail.links || [];
  byId('res-links').innerHTML = links.length
    ? links.map((link) => `
      <div class="detail-link">
        ${link.displayText ? `<strong>${escapeHtml(link.displayText)}</strong><br>` : ''}
        <div class="mono">${escapeHtml(link.actualUrl || '')}</div>
        <div class="detail-link-meta">
          ${escapeHtml(link.domain || 'Unknown domain')}
          ${link.usesShortener ? ' · shortener' : ''}
          ${link.displayDomainDiffers ? ' · display mismatch' : ''}
          ${link.looksSuspicious ? ' · suspicious domain' : ''}
        </div>
      </div>
    `).join('')
    : '<div class="detail-link">No links extracted from message body</div>';

  const attachments = detail.attachmentWarnings || [];
  byId('res-attachments').innerHTML = attachments.length
    ? attachments.map((item) => `<div class="detail-flag">${escapeHtml(item.filename)} - ${escapeHtml(item.warning)}</div>`).join('')
    : '<div class="detail-link">No risky attachments detected</div>';

  const feedbackStatus = byId('feedback-status');
  if (detail.feedback) {
    feedbackStatus.textContent = `Saved feedback: ${detail.feedback.replace(/_/g, ' ')}`;
    feedbackStatus.classList.remove('hidden');
  } else {
    feedbackStatus.classList.add('hidden');
    feedbackStatus.textContent = '';
  }

  byId('safe-sender-btn').textContent = detail.senderStatus === 'safe' ? 'Safe Sender Added' : 'Add to Safe Senders';
  byId('block-sender-btn').textContent = detail.senderStatus === 'blocked' ? 'Blocked Sender Added' : 'Block Sender';

  renderThreatInvestigation(detail);
  renderThreatIntel(detail);
  renderChat(detail);

  setPanelState('panel-results');
}

function buildAnalyzedEntry(emailObj) {
  return {
    riskLevel: emailObj.riskLevel,
    riskScore: emailObj.riskScore,
    confidenceScore: emailObj.confidenceScore,
    reasons: emailObj.reasons || [],
    detectedLinksSummary: emailObj.detectedLinksSummary || {},
    attachmentWarnings: emailObj.attachmentWarnings || [],
    feedback: emailObj.feedback || null,
    senderStatus: emailObj.senderStatus || 'neutral',
    detail: null,
  };
}

async function selectEmail(id) {
  setCurrentSelectedId(id);
  renderPipeline();
  window.requestAnimationFrame(() => {
    document.querySelector('.email-row.is-selected')?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  });

  const email = state.emails.find((item) => item.id === id);
  const data = state.analyzed[id];

  if (!email || !data) {
    byId('panel-error-text').textContent = 'No analysis available for this email.';
    setPanelState('panel-error');
    return;
  }

  if (!data.detail) {
    setPanelState('panel-scanning');
    try {
      const response = await fetch(`/api/emails/${encodeURIComponent(id)}`);
      const detail = await response.json();
      if (!response.ok) throw new Error(detail.error || 'Failed to load full email detail');

      const domainResult = analyzeDomain(extractDomain(detail.senderEmail));
      data.detail = {
        ...detail,
        domainSignals: domainResult.signals,
        spoofed: domainResult.spoofed,
        authChain: parseAuthResults(detail.headers || {}),
        authFlags: buildAuthFlags(detail.headers || {}),
      };
      data.feedback = detail.feedback || null;
      data.senderStatus = detail.senderStatus || 'neutral';
      email.riskLevel = detail.riskLevel || email.riskLevel;
      email.riskScore = detail.riskScore ?? email.riskScore;
      email.confidenceScore = detail.confidenceScore ?? email.confidenceScore;
      email.reasons = detail.reasons || email.reasons;
    } catch (error) {
      byId('panel-error-text').textContent = error.message;
      setPanelState('panel-error');
      return;
    }
  }

  state.selectedDetail = data.detail;
  renderResults(email, data.detail);
}

function syncInspectorForCurrentTab() {
  const selectedId = currentSelectedId();
  if (!selectedId) {
    syncEmptyPanel();
    return;
  }

  const visibleIds = selectedEmailIdsForTab(currentTab());
  if (!visibleIds.has(selectedId)) {
    clearSelectedId();
    syncEmptyPanel();
    return;
  }

  const email = state.emails.find((item) => item.id === selectedId);
  const data = state.analyzed[selectedId];
  if (!email || !data?.detail) {
    syncEmptyPanel();
    return;
  }

  state.selectedDetail = data.detail;
  renderResults(email, data.detail);
}

function renderLoadMoreButton() {
  const actions = byId('scan-actions');
  const show = Boolean(state.nextPageToken) && !state.searchQuery;
  if (actions) actions.classList.toggle('hidden', !show);
}

function renderOverview(total, scamCount, spamCount, reviewCount, safeCount) {
  const chartValues = [
    Math.max(8, Math.round(total * 0.22)),
    Math.max(12, Math.round(total * 0.31)),
    Math.max(10, Math.round(total * 0.27)),
    Math.max(14, Math.round(total * 0.33)),
    Math.max(11, Math.round(total * 0.25)),
    Math.max(6, Math.round(total * 0.12)),
    Math.max(18, Math.round(total * 0.42)),
  ];
  const maxValue = Math.max(...chartValues, 1);
  const stepX = 800 / (chartValues.length - 1);
  const points = chartValues.map((value, index) => {
    const x = index * stepX;
    const y = 190 - ((value / maxValue) * 130);
    return [x, y];
  });
  const linePath = points.map(([x, y], index) => `${index === 0 ? 'M' : 'L'} ${x} ${y}`).join(' ');
  const areaPath = `${linePath} L 800 220 L 0 220 Z`;
  byId('activity-line').setAttribute('d', linePath);
  byId('activity-area').setAttribute('d', areaPath);

  const rows = [
    ['Threat', scamCount, 'var(--threat)'],
    ['Spam', spamCount, 'var(--spam)'],
    ['Caution', reviewCount, 'var(--caution)'],
    ['Safe', safeCount, 'var(--safe)'],
  ];
  const largest = Math.max(...rows.map((row) => row[1]), 1);
  byId('breakdown-bars').innerHTML = rows.map(([label, value, color]) => `
    <div class="breakdown-row">
      <div class="breakdown-label-row">
        <strong>${escapeHtml(label)}</strong>
        <span class="breakdown-value mono">${value.toLocaleString()}</span>
      </div>
      <div class="breakdown-track">
        <span class="breakdown-fill" style="width:${Math.max(8, Math.round((value / largest) * 100))}%; background:${color}"></span>
      </div>
    </div>
  `).join('');

  const trendText = total
    ? `Threat rate ${scamCount + spamCount > reviewCount ? 'down' : 'stable'} this week`
    : 'Waiting for inbox data';
  byId('breakdown-footer-text').textContent = trendText;
}

function initOverlayFx() {
  const rain = byId('matrix-rain');
  const glyphs = byId('matrix-glyphs');
  if (!rain || !glyphs) return;

  const chars = '01ABCDEFGHIJKLMNOPQRSTUVWXYZ#$%&*';
  rain.innerHTML = '';
  glyphs.innerHTML = '';

  for (let index = 0; index < 18; index += 1) {
    const column = document.createElement('div');
    column.className = 'matrix-column';
    column.style.left = `${4 + index * 5.2}%`;
    column.style.animationDuration = `${7 + (index % 5)}s`;
    column.style.animationDelay = `${(index % 6) * -1.2}s`;
    column.textContent = Array.from({ length: 28 }, () => chars[Math.floor(Math.random() * chars.length)]).join('\n');
    rain.appendChild(column);
  }

  for (let index = 0; index < 26; index += 1) {
    const glyph = document.createElement('span');
    glyph.className = 'matrix-glyph';
    glyph.style.left = `${6 + (index % 9) * 10}%`;
    glyph.style.top = `${8 + Math.floor(index / 9) * 22}%`;
    glyph.textContent = chars[Math.floor(Math.random() * chars.length)];
    glyph.addEventListener('mouseenter', () => {
      glyph.classList.add('is-active');
      glyph.textContent = chars[Math.floor(Math.random() * chars.length)];
      window.setTimeout(() => glyph.classList.remove('is-active'), 240);
    });
    glyphs.appendChild(glyph);
  }

  if (glyphInterval) window.clearInterval(glyphInterval);
  glyphInterval = window.setInterval(() => {
    rain.querySelectorAll('.matrix-column').forEach((column) => {
      column.textContent = Array.from({ length: 28 }, () => chars[Math.floor(Math.random() * chars.length)]).join('\n');
    });
    glyphs.querySelectorAll('.matrix-glyph').forEach((glyph) => {
      if (!glyph.classList.contains('is-active')) {
        glyph.textContent = chars[Math.floor(Math.random() * chars.length)];
      }
    });
  }, 320);
}

async function fetchPage(pageToken) {
  const params = new URLSearchParams();
  if (pageToken) params.set('pageToken', pageToken);
  if (state.searchQuery) params.set('q', state.searchQuery);

  const baseUrl = state.searchQuery ? '/api/search' : '/api/emails';
  const queryString = params.toString();
  const response = await fetch(queryString ? `${baseUrl}?${queryString}` : baseUrl);
  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || 'Failed to load emails');
  }

  return data;
}

function updateLoadButtonLoading(loading) {
  const button = byId('load-more-btn');
  button.disabled = loading;
  button.textContent = loading ? 'Scanning Next 20...' : 'Scan Next 20 Emails';
  const scanAllButton = byId('scan-all-btn');
  if (scanAllButton) {
    scanAllButton.disabled = loading;
    scanAllButton.textContent = loading ? 'Scanning Inbox...' : 'Scan Entire Inbox';
  }
}

async function scanEntireInbox() {
  if (!state.nextPageToken || state.searchQuery) return;
  updateLoadButtonLoading(true);
  while (state.nextPageToken) {
    await loadEmailsInternal(state.nextPageToken, true, { silent: true, keepButtonLoading: true });
  }
  updateLoadButtonLoading(false);
}

async function loadEmails(pageToken, append) {
  return loadEmailsInternal(pageToken, append, { silent: false });
}

async function loadEmailsInternal(pageToken, append, options = {}) {
  const spinner = byId('sync-spinner');
  const modeLabel = state.searchQuery ? 'search' : (append ? 'pagination' : 'inbox');
  let waitProgress = 18;
  let waitTick = null;
  let waitLogTick = null;

  if (!options.silent) {
    spinner.textContent = '...';
    spinner.classList.remove('hidden');
  }

  if (!append) {
    state.selectedDetail = null;
    setPanelState('panel-scanning');
  }

  if (!options.silent) {
    setOverlayVisibility(true);
    resetOverlay(modeLabel);
    appendOverlayLog(
      modeLabel === 'search'
        ? `gmail: executing query "${state.searchQuery}"`
        : pageToken
          ? 'gmail: requesting next page of inbox results'
          : 'gmail: requesting inbox messages'
    );
    setOverlayStage('Contacting Gmail...', 'Fetching message metadata and queued ML analysis.');
    setOverlayProgress(18);
    waitTick = window.setInterval(() => {
      waitProgress = Math.min(waitProgress + 4, 60);
      setOverlayProgress(waitProgress);
    }, 350);
    waitLogTick = window.setTimeout(() => {
      appendOverlayLog('gmail: inbox metadata still loading', true);
      setOverlayStage('Contacting Gmail...', 'Loading the latest 20 emails from this account.');
    }, 1200);
  }

  try {
    const data = await fetchPage(pageToken);
    window.clearInterval(waitTick);
    window.clearTimeout(waitLogTick);
    const newEmails = data.emails || [];
    const total = Math.max(newEmails.length, 1);

    if (!options.silent) {
      appendOverlayLog(`gmail: received ${newEmails.length} emails`);
      appendOverlayLog('ml: applying local threat classifications', true);
      setOverlayStage('Applying local model results...', `Processing ${newEmails.length} analyzed emails.`);
      setOverlayProgress(45);
    }

    newEmails.forEach((email, index) => {
      state.analyzed[email.id] = {
        ...(state.analyzed[email.id] || {}),
        ...buildAnalyzedEntry(email),
      };
      if (!options.silent) {
        setOverlayProgress(45 + Math.round(((index + 1) / total) * 45));
      }

      if (!options.silent && (index < 5 || (index + 1) % 10 === 0 || index === newEmails.length - 1)) {
        appendOverlayLog(
          `analysis: ${index + 1}/${newEmails.length} ${(email.subject || '(No subject)').slice(0, 72)}`,
          index >= 5
        );
      }
    });

    state.emails = append ? [...state.emails, ...newEmails] : newEmails;
    state.nextPageToken = data.nextPageToken || null;

    if (!options.silent) {
      appendOverlayLog('ui: rendering threat console');
      setOverlayStage('Rendering ThreatDecoder AI...', 'Updating stats, filters, and email detail views.');
      setOverlayProgress(96);
    }

    renderStats();
    renderPipeline();
    renderCampaignBanner();
    renderLoadMoreButton();

    if (!append) {
      setPanelState('panel-empty');
    }

    ['all', 'suspicious'].forEach((tab) => {
      const selectedId = state.selectedByTab[tab];
      if (!selectedId) return;
      if (!selectedEmailIdsForTab(tab).has(selectedId)) {
        clearSelectedId(tab);
      }
    });

    syncInspectorForCurrentTab();

    if (!options.silent) {
      appendOverlayLog('done: inbox scan complete', true);
      setOverlayProgress(100);
      window.setTimeout(() => setOverlayVisibility(false), 220);
    }
  } catch (error) {
    window.clearInterval(waitTick);
    window.clearTimeout(waitLogTick);
    if (!options.silent) {
      appendOverlayLog(`error: ${error.message}`);
      setOverlayStage('Scan failed', error.message);
      setOverlayProgress(100);
    }

    if (append) {
      alert(`Error loading more emails: ${error.message}`);
      if (!options.silent) setOverlayVisibility(false);
    } else {
      byId('pipeline-list').innerHTML = `<div class="list-placeholder" style="color:var(--threat)">${escapeHtml(error.message)}</div>`;
      byId('panel-error-text').textContent = error.message;
      setPanelState('panel-error');
      if (!options.silent) window.setTimeout(() => setOverlayVisibility(false), 320);
    }
  } finally {
    window.clearInterval(waitTick);
    window.clearTimeout(waitLogTick);
    if (!options.silent) {
      spinner.textContent = '';
      spinner.classList.add('hidden');
    }
    if (!options.keepButtonLoading) {
      updateLoadButtonLoading(false);
    }
  }
}

function clearSearch() {
  state.searchQuery = '';
  byId('search-input').value = '';
  byId('clear-search-btn').classList.add('hidden');
  byId('mail-search-row')?.classList.add('hidden');
  loadEmails();
}

function selectedEmail() {
  return state.emails.find((item) => item.id === currentSelectedId()) || null;
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}

async function refreshSelectedDetail() {
  const selectedId = currentSelectedId();
  if (!selectedId) return;
  const entry = state.analyzed[selectedId];
  if (entry) entry.detail = null;
  await selectEmail(selectedId);
  renderPipeline();
  renderStats();
}

async function saveFeedback(feedback) {
  const email = selectedEmail();
  if (!email) return;
  await postJson('/api/feedback', { id: email.id, feedback });
  state.analyzed[email.id].feedback = feedback;
  if (state.analyzed[email.id].detail) {
    state.analyzed[email.id].detail.feedback = feedback;
  }
  if (state.selectedDetail) {
    state.selectedDetail.feedback = feedback;
    renderResults(email, state.selectedDetail);
  }
}

async function updateSenderList(action) {
  const email = selectedEmail();
  if (!email?.senderEmail) return;
  await postJson('/api/sender-list', { senderEmail: email.senderEmail, action });
  await refreshSelectedDetail();
}

function exportSelectedReport() {
  const email = selectedEmail();
  const detail = state.selectedDetail;
  if (!email || !detail) return;

  const report = {
    sender: detail.senderEmail || email.senderEmail,
    subject: detail.subject || email.subject,
    date: detail.date || detail.timestamp || email.timestamp,
    riskLevel: detail.riskLevel || email.riskLevel,
    confidenceScore: detail.confidenceScore || email.confidenceScore,
    reasons: detail.reasons || [],
    linkFindings: detail.links || [],
    attachmentWarnings: detail.attachmentWarnings || [],
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `guardmail-report-${email.id}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function bootDashboard() {
  if (!byId('sync-btn')) return;
  initTheme();
  initAccountMenu();
  initSearchToggle();
  initOverlayFx();
  setInspectorTab('overview');
  renderCopilot();

  byId('sync-btn').addEventListener('click', () => loadEmails());
  byId('tab-suspicious').addEventListener('click', () => {
    state.filter = 'suspicious';
    renderPipeline();
    syncInspectorForCurrentTab();
  });
  byId('tab-all').addEventListener('click', () => {
    state.filter = 'all';
    renderPipeline();
    syncInspectorForCurrentTab();
  });

  byId('search-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const query = byId('search-input').value.trim();
    if (!query) return;
    state.searchQuery = query;
    byId('clear-search-btn').classList.remove('hidden');
    loadEmails();
  });

  byId('search-input').addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      clearSearch();
    }
  });

  byId('clear-search-btn').addEventListener('click', clearSearch);

  byId('load-more-btn').addEventListener('click', async () => {
    updateLoadButtonLoading(true);
    await loadEmails(state.nextPageToken, true);
  });

  byId('scan-all-btn').addEventListener('click', async () => {
    await scanEntireInbox();
  });

  byId('delete-suspicious-btn').addEventListener('click', async () => {
    const suspicious = getSuspiciousEmails();
    if (!suspicious.length) return;

    const previewList = suspicious
      .slice(0, 8)
      .map((email) => `- ${email.subject || '(No subject)'}`)
      .join('\n');
    const suffix = suspicious.length > 8 ? `\n- ...and ${suspicious.length - 8} more` : '';
    if (!confirm(`Move these ${suspicious.length} suspicious emails to Gmail trash?\n\n${previewList}${suffix}\n\nThey will not be permanently deleted.`)) {
      return;
    }

    const ids = suspicious.map((email) => email.id);

    try {
      const response = await fetch('/api/delete-emails', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids }),
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to delete emails');
      }

      state.emails = state.emails.filter((email) => !ids.includes(email.id));
      ids.forEach((id) => delete state.analyzed[id]);

      ['all', 'suspicious'].forEach((tab) => {
        if (ids.includes(state.selectedByTab[tab])) {
          clearSelectedId(tab);
        }
      });
      syncInspectorForCurrentTab();

      renderStats();
      renderPipeline();
      renderCampaignBanner();
      alert(`${ids.length} suspicious emails moved to trash`);
    } catch (error) {
      alert(`Error: ${error.message}`);
    }
  });

  byId('feedback-safe-btn').addEventListener('click', () => saveFeedback('mark_safe').catch((error) => alert(`Error: ${error.message}`)));
  byId('feedback-scam-btn').addEventListener('click', () => saveFeedback('mark_scam').catch((error) => alert(`Error: ${error.message}`)));
  byId('feedback-unsure-btn').addEventListener('click', () => saveFeedback('not_sure').catch((error) => alert(`Error: ${error.message}`)));
  byId('safe-sender-btn').addEventListener('click', () => updateSenderList('safe').catch((error) => alert(`Error: ${error.message}`)));
  byId('block-sender-btn').addEventListener('click', () => updateSenderList('block').catch((error) => alert(`Error: ${error.message}`)));
  byId('export-report-btn').addEventListener('click', exportSelectedReport);
  ['overview', 'investigation', 'intel'].forEach((tab) => {
    byId(`inspector-tab-${tab}`).addEventListener('click', () => setInspectorTab(tab));
  });
  byId('copilot-toggle').addEventListener('click', () => setCopilotOpen(!state.copilotOpen));
  byId('copilot-close').addEventListener('click', () => setCopilotOpen(false));
  byId('copilot-form').addEventListener('submit', (event) => {
    event.preventDefault();
    submitCopilotQuestion(byId('copilot-input').value);
  });
  byId('copilot-input').addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      setCopilotOpen(false);
    }
  });

  renderLoadMoreButton();
  loadEmails();
}

bootDashboard();
