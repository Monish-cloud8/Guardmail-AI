(function initGuardMailAssistant() {
  const APP_ANSWERS = {
    scan: 'Use Refresh to rescan recent messages, Scan Next 20 Emails for the next page, or Scan Entire Inbox for a full sweep.',
    suspicious: 'Suspicious means local sender, language, link, attachment, or authentication checks found warning signs. Open the email to see the exact reasons.',
    safe: 'Safe means the local checks found no strong threat signals. It is still wise to verify unexpected requests before clicking or replying.',
    confidence: 'Confidence shows how strongly the local model and rules agree with the displayed risk level. It is not a guarantee by itself.',
    risk: 'Risk level summarizes the local analysis: Safe, Unknown, Suspicious, or Scam Alert. Higher levels call for more caution.',
    threat_intel: 'Threat Intelligence combines local sender-domain, link, attachment, authentication, safe-list, and block-list checks.',
    links: 'Open an email and check its Links section. GuardMail locally flags shorteners, misleading display domains, and suspicious domain patterns.',
    attachments: 'Open an email and check Attachment Warnings. GuardMail locally highlights risky file types and attachment signals.',
    safe_senders: 'Open an email, then choose Add to Safe Senders. This lowers future risk unless stronger scam signals are present.',
    blocked_senders: 'Open an email, then choose Block Sender. GuardMail records that sender locally and treats future messages as higher risk.',
    trash: 'Open the Suspicious tab and choose Move Suspicious to Trash. Gmail trash is recoverable if you change your mind.',
    how_it_works: 'GuardMail uses a local phishing model plus header, sender-domain, link, attachment, and language rules. It does not call a hosted AI service.',
  };

  const includesAny = (text, terms) => terms.some((term) => text.includes(term));

  function riskyLinkSummary(email) {
    const links = email.links || [];
    if (!links.length) return 'No links were extracted from this email.';
    return links.map((link) => {
      const flags = [];
      if (link.usesShortener) flags.push('URL shortener');
      if (link.displayDomainDiffers) flags.push('display-domain mismatch');
      if (link.looksSuspicious) flags.push('suspicious domain');
      return `${link.domain || 'Unknown domain'}${flags.length ? ` (${flags.join(', ')})` : ''}`;
    }).join('; ');
  }

  function attachmentSummary(email) {
    const warnings = email.attachmentWarnings || [];
    if (!warnings.length) return 'No risky attachments were detected.';
    return `Attachment warnings: ${warnings.map((item) => item.filename || 'Unnamed attachment').join(', ')}.`;
  }

  function generateEmailExplanation(email) {
    if (!email) return 'Select an email first so I can explain its analysis.';
    const reasons = [...(email.reasons || []), ...(email.domainSignals || [])];
    const risk = email.riskLevel || 'Unknown';
    const confidence = email.confidenceScore ?? email.riskScore ?? 0;
    const summary = reasons.length
      ? `It is marked ${risk} at ${confidence}% confidence because of: ${reasons.slice(0, 3).join(', ')}.`
      : risk === 'Safe'
        ? `It is marked Safe at ${confidence}% confidence because no strong threat signals were found.`
        : `It is marked ${risk} at ${confidence}% confidence by the local analysis.`;
    const action = risk === 'Safe'
      ? 'Keep normal caution, especially for unexpected requests.'
      : risk === 'Scam Alert'
        ? 'Do not click links or open attachments; verify independently or move it to trash.'
        : 'Verify the sender through another channel before interacting.';
    return `${summary} ${action}`;
  }

  function detectAssistantIntent(question, hasSelectedEmail = false) {
    const q = String(question || '').trim().toLowerCase();
    if (!q) return 'help';
    if (includesAny(q, ['explain this like', 'like i am 12', "like i'm 12", 'in simple terms'])) return hasSelectedEmail ? 'email_simple' : 'how_it_works';
    if (includesAny(q, ['what should i do', 'what do i do', 'next step', 'action should'])) return hasSelectedEmail ? 'email_action' : 'help';
    if (includesAny(q, ['why is this', 'why was this', 'why suspicious', 'why safe', 'explain this email'])) return hasSelectedEmail ? 'email_explain' : 'suspicious';
    if (includesAny(q, ['trust this sender', 'trust the sender', 'trust this email', 'is this safe', 'does this look safe'])) return hasSelectedEmail ? 'email_trust' : 'safe_senders';
    if (includesAny(q, ['scan', 'inbox', 'refresh'])) return 'scan';
    if (includesAny(q, ['confidence'])) return hasSelectedEmail ? 'email_confidence' : 'confidence';
    if (includesAny(q, ['risk level', 'risk score'])) return hasSelectedEmail ? 'email_risk' : 'risk';
    if (includesAny(q, ['threat intelligence', 'threat intel'])) return hasSelectedEmail ? 'email_intel' : 'threat_intel';
    if (includesAny(q, ['attachment', 'file'])) return hasSelectedEmail ? 'email_attachments' : 'attachments';
    if (includesAny(q, ['link', 'url'])) return hasSelectedEmail ? 'email_links' : 'links';
    if (includesAny(q, ['safe sender', 'allowlist', 'whitelist'])) return 'safe_senders';
    if (includesAny(q, ['blocked sender', 'blocklist', 'block sender'])) return 'blocked_senders';
    if (includesAny(q, ['trash', 'delete', 'remove email'])) return 'trash';
    if (includesAny(q, ['how does', 'how do you', 'how it works', 'detect scam'])) return 'how_it_works';
    if (includesAny(q, ['suspicious', 'phishing', 'scam'])) return hasSelectedEmail ? 'email_explain' : 'suspicious';
    if (includesAny(q, ['safe email', 'safe emails'])) return hasSelectedEmail ? 'email_trust' : 'safe';
    return 'out_of_scope';
  }

  function generateAppHelpAnswer(intent, context = {}) {
    if (intent === 'help') {
      return context.selectedEmail
        ? 'Ask why this email was flagged, whether to trust it, or about its links, attachments, confidence, and next steps.'
        : 'Ask how to scan your inbox, understand risk and confidence, manage senders, or move suspicious messages to trash.';
    }
    return APP_ANSWERS[intent] || 'I can help with GuardMail AI and the selected email analysis.';
  }

  function answerSelectedEmail(intent, email) {
    if (!email) return 'Select an email first so I can use its analysis.';
    const risk = email.riskLevel || 'Unknown';
    const confidence = email.confidenceScore ?? email.riskScore ?? 0;
    if (intent === 'email_links') return riskyLinkSummary(email);
    if (intent === 'email_attachments') return attachmentSummary(email);
    if (intent === 'email_confidence') return `Confidence is ${confidence}%. That shows how strongly the local model and rules agree with the ${risk} result.`;
    if (intent === 'email_intel') {
      const linkCount = (email.links || []).length;
      const attachmentCount = (email.attachmentWarnings || []).length;
      return `${generateEmailExplanation(email)} Threat Intelligence reviewed ${linkCount} link(s), ${attachmentCount} attachment warning(s), and the sender is ${email.senderStatus || 'not listed'}.`;
    }
    if (intent === 'email_risk') return generateEmailExplanation(email);
    if (intent === 'email_simple') return risk === 'Safe'
      ? 'This email looks okay because GuardMail did not find strong warning signs.'
      : `This email may be trying to trick you. GuardMail marked it ${risk}, so do not rush to click or reply.`;
    if (intent === 'email_trust') return risk === 'Safe'
      ? `It currently looks safe at ${confidence}% confidence, but verify any unexpected request.`
      : `I would not trust it yet. It is marked ${risk} at ${confidence}% confidence. Verify the sender another way.`;
    return generateEmailExplanation(email);
  }

  function answerAssistantQuestion(question, selectedEmail, appState = {}) {
    if (window.GuardMailAssistant.futureModel.answer) {
      return window.GuardMailAssistant.futureModel.answer(question, selectedEmail, appState);
    }
    const intent = detectAssistantIntent(question, Boolean(selectedEmail));
    return intent.startsWith('email_')
      ? answerSelectedEmail(intent, selectedEmail)
      : generateAppHelpAnswer(intent, { ...appState, selectedEmail });
  }

  window.GuardMailAssistant = {
    detectAssistantIntent,
    answerAssistantQuestion,
    generateEmailExplanation,
    generateAppHelpAnswer,
    answerQuestion(question, context = {}) {
      return answerAssistantQuestion(question, context.selectedEmail, context);
    },
    futureModel: {
      // ponytail: replace this hook with a local model later; the UI and fallback rules stay unchanged.
      answer: null,
    },
  };

  console.assert(detectAssistantIntent('How do I scan my inbox?') === 'scan');
  console.assert(detectAssistantIntent('Are the links safe?', true) === 'email_links');
  console.assert(answerAssistantQuestion('Tell me a joke', null) === 'I can help with GuardMail AI and the selected email analysis.');
})();
