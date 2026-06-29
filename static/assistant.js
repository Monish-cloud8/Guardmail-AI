(function initGuardMailAssistant() {
  const APP_ANSWERS = {
    scan: 'Use Refresh to rescan the latest inbox emails. Use "Scan Next 20 Emails" or "Scan Entire Inbox" when you want a wider sweep.',
    scam_alert: 'Scam Alert is the highest risk level in this app. It means the local model and rule checks both found strong fraud signals.',
    threat_intel: 'Threat Intelligence combines local checks on sender reputation, link patterns, attachment risk, and authentication results.',
    trash: 'Use "Move Suspicious to Trash" from the Suspicious tab. The app moves messages to Gmail trash so they can still be recovered.',
    whitelist: 'Open an email first, then use "Add to Safe Senders" in the analysis panel. Safe senders lower risk unless stronger scam signals are present.',
    confidence: 'Confidence is the local model confidence behind the final risk level. Higher confidence means the model and rules agree more strongly.',
    detection: 'This app uses your local phishing model, header forensics, link analysis, attachment checks, and sender/domain rules. No hosted AI is used.',
  };

  function extractDomain(value) {
    if (!value) return '';
    const match = String(value).match(/@([^>\s]+)/);
    return (match ? match[1] : value).toLowerCase().replace(/^www\./, '').trim();
  }

  function hasRiskyLinks(detail) {
    return (detail.links || []).some((link) => link.usesShortener || link.displayDomainDiffers || link.looksSuspicious);
  }

  function riskyLinkSummary(detail) {
    const links = detail.links || [];
    if (!links.length) return 'No links were extracted from this email.';
    return links
      .map((link) => {
        const tags = [];
        if (link.usesShortener) tags.push('shortener');
        if (link.displayDomainDiffers) tags.push('display mismatch');
        if (link.looksSuspicious) tags.push('suspicious domain');
        return `${link.domain || 'unknown domain'}${tags.length ? ` (${tags.join(', ')})` : ''}`;
      })
      .join('; ');
  }

  function attachmentSummary(detail) {
    const attachments = detail.attachmentWarnings || [];
    if (!attachments.length) return 'No risky attachments were detected.';
    return attachments.map((item) => `${item.filename} (${item.warning})`).join('; ');
  }

  function generateExplanation(detail) {
    const reasons = detail.reasons || [];
    const auth = detail.authChain || {};
    const sender = extractDomain(detail.senderEmail || '');
    const points = [];

    if (reasons.length) points.push(`Main reasons: ${reasons.slice(0, 3).join(', ')}.`);
    if (detail.domainSignals?.length) points.push(`Sender domain checks found: ${detail.domainSignals.slice(0, 2).join(', ')}.`);
    if (hasRiskyLinks(detail)) points.push(`Link checks found: ${riskyLinkSummary(detail)}.`);
    if ((detail.attachmentWarnings || []).length) points.push(`Attachment checks found: ${attachmentSummary(detail)}.`);
    if (auth.spf === 'FAIL' || auth.dkim === 'FAIL' || auth.dmarc === 'FAIL') points.push('Authentication checks failed for at least one of SPF, DKIM, or DMARC.');
    if (!points.length && detail.riskLevel === 'Safe') points.push('No strong fraud indicators were found in the sender, links, attachments, or language.');
    if (!points.length) points.push('The current local checks did not produce a specific explanation beyond the final risk score.');

    return {
      sender,
      summary: points.join(' '),
      recommendation: detail.riskLevel === 'Safe'
        ? 'This looks okay from the current checks. Keep normal email caution.'
        : detail.riskLevel === 'Scam Alert'
          ? 'Do not click links or open attachments. Move it to trash or verify through another channel.'
          : detail.riskLevel === 'Suspicious'
            ? 'Treat it carefully and verify the sender before interacting.'
            : 'Review the sender, links, and message intent before acting.',
    };
  }

  function detectIntent(question, hasSelectedEmail) {
    const q = String(question || '').trim().toLowerCase();
    if (!q) return 'help';
    if (q.includes('scan') || q.includes('inbox') || q.includes('refresh')) return 'scan';
    if (q.includes('scam alert') || q.includes('risk level')) return 'scam_alert';
    if (q.includes('threat intelligence') || q.includes('intel')) return 'threat_intel';
    if (q.includes('trash') || q.includes('delete') || q.includes('move')) return 'trash';
    if (q.includes('white') || q.includes('safe sender') || q.includes('allow')) return 'whitelist';
    if (q.includes('confidence') || q.includes('score')) return 'confidence';
    if (q.includes('how') && q.includes('detect')) return 'detection';
    if (hasSelectedEmail && (q.includes('why') || q.includes('explain'))) return 'email_explain';
    if (hasSelectedEmail && (q.includes('safe') || q.includes('trust'))) return 'email_trust';
    if (hasSelectedEmail && q.includes('link')) return 'email_links';
    if (hasSelectedEmail && q.includes('attachment')) return 'email_attachments';
    if (hasSelectedEmail && (q.includes('do') || q.includes('should i') || q.includes('action'))) return 'email_action';
    if (hasSelectedEmail && (q.includes('12') || q.includes('simple'))) return 'email_simple';
    return hasSelectedEmail ? 'email_explain' : 'out_of_scope';
  }

  function answerAboutApplication(intent, context) {
    if (intent === 'help') {
      return context.selectedEmail
        ? 'Ask about why the selected email was flagged, whether its links look risky, whether you should trust the sender, or what action to take.'
        : 'Ask how scanning works, what Scam Alert means, how confidence works, how to move suspicious emails to trash, or how to safe-list a sender.';
    }
    if (APP_ANSWERS[intent]) return APP_ANSWERS[intent];
    return 'I can currently answer questions about this application and the selected email.';
  }

  function answerAboutSelectedEmail(intent, context) {
    const detail = context.selectedEmail;
    if (!detail) return 'Select an email first, then I can explain its sender, links, attachments, and risk score.';

    const explanation = generateExplanation(detail);
    const riskLabel = detail.riskLevel || 'Safe';
    const confidence = detail.confidenceScore ?? detail.riskScore ?? 0;

    if (intent === 'email_simple') {
      return riskLabel === 'Safe'
        ? 'This one looks okay. I did not find strong warning signs.'
        : `This email might be trying to trick you. The main warning is that it looks ${riskLabel.toLowerCase()} and the app found scam-like patterns.`;
    }
    if (intent === 'email_trust') {
      return riskLabel === 'Safe'
        ? `This currently looks safe. Confidence is ${confidence}%, and the local checks did not find major fraud indicators.`
        : `I would be careful. This email is marked ${riskLabel} at ${confidence}% confidence. ${explanation.recommendation}`;
    }
    if (intent === 'email_links') {
      return riskyLinkSummary(detail);
    }
    if (intent === 'email_attachments') {
      return attachmentSummary(detail);
    }
    if (intent === 'email_action') {
      return explanation.recommendation;
    }
    return `${explanation.summary} ${explanation.recommendation}`;
  }

  function answerQuestion(question, context) {
    if (window.GuardMailAssistant.futureModel.answer) {
      return window.GuardMailAssistant.futureModel.answer(question, context);
    }

    const hasSelectedEmail = Boolean(context.selectedEmail);
    const intent = detectIntent(question, hasSelectedEmail);

    if (intent.startsWith('email_')) {
      return answerAboutSelectedEmail(intent, context);
    }
    return answerAboutApplication(intent, context);
  }

  window.GuardMailAssistant = {
    detectIntent,
    answerQuestion,
    generateExplanation,
    answerAboutApplication,
    answerAboutSelectedEmail,
    futureModel: {
      // ponytail: swap this with your own local NLP model later without changing the copilot UI.
      answer: null,
    },
  };
})();
