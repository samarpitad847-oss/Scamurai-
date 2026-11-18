// Pure Vanilla JavaScript for Scamurai

// Set VITE_API_BASE_URL when building the separately hosted frontend.
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

const QUIZ_QUESTIONS = [
  {
    vector: 'messages',
    vectorTitle: 'Messages',
    scenarioTitle: 'WhatsApp Forward from a Contact',
    prompt: 'A friend on WhatsApp sends this message out of nowhere. What is the biggest red flag?',
    artifact: '"Hey! I accidentally typed your phone number when resetting my account and it sent you a 6-digit SMS code. Please send it back to me quick!"',
    options: [
      { id: 'a', label: 'It does not include a clickable website link', isCorrect: false },
      { id: 'b', label: 'They are asking you to forward a 6-digit verification code (OTP)', isCorrect: true },
      { id: 'c', label: 'The message uses an exclamation mark', isCorrect: false },
    ],
    explanation: 'That 6-digit code is actually YOUR WhatsApp or bank login code. Scammers take over a friend’s account first, then message their contacts to steal the next account.',
    takeaway: 'Rule: Never share a one-time code with anyone—not even a close friend or family member.',
  },
  {
    vector: 'urls',
    vectorTitle: 'URLs & Links',
    scenarioTitle: 'Domain Check Before Clicking',
    prompt: 'You receive a security alert linking to the URL below. Which part determines the REAL website?',
    artifact: 'https://paypal.com.account-verify-alerts.xyz/login',
    options: [
      { id: 'a', label: 'paypal.com at the very start of the address', isCorrect: false },
      { id: 'b', label: 'The https:// padlock protocol', isCorrect: false },
      { id: 'c', label: 'account-verify-alerts.xyz right before the first single "/" slash', isCorrect: true },
    ],
    explanation: 'In any URL, everything before the root domain ("paypal.com.") is just a subdomain created by the attacker. The actual destination is account-verify-alerts.xyz.',
    takeaway: 'Rule: Always read right-to-left from the first single "/" slash to find the real domain.',
  },
  {
    vector: 'attachments',
    vectorTitle: 'Email Attachments',
    scenarioTitle: 'Email Invoice Attachment',
    prompt: 'An email marked "OVERDUE" includes the file below. Why is it dangerous?',
    artifact: 'Attached: Statement_88412.pdf.exe (Size: 410 KB)',
    options: [
      { id: 'a', label: 'PDF files over 400 KB are usually corrupted', isCorrect: false },
      { id: 'b', label: 'Its true extension is .exe (an executable program disguised as a PDF)', isCorrect: true },
      { id: 'c', label: 'The filename uses underscores instead of spaces', isCorrect: false },
    ],
    explanation: 'Operating systems read only the final extension (.exe). Putting ".pdf" before ".exe" tricks people who glance quickly into running malware.',
    takeaway: 'Rule: Look at the final letters after the very last dot before opening any attachment.',
  },
  {
    vector: 'urls',
    vectorTitle: 'URLs & Links',
    scenarioTitle: 'Deceptive "@" Link Trick',
    prompt: 'If you click the link below, which website does your browser actually connect to?',
    artifact: 'https://chase.com@secure-login-verify.top/auth',
    options: [
      { id: 'a', label: 'chase.com because it comes right after https://', isCorrect: false },
      { id: 'b', label: 'secure-login-verify.top because everything before "@" is ignored as a username', isCorrect: true },
      { id: 'c', label: 'Neither—browsers block all links containing "@"', isCorrect: false },
    ],
    explanation: 'In standard URL syntax (user@host), everything before "@" is treated as user credentials and discarded, sending you straight to secure-login-verify.top.',
    takeaway: 'Rule: Be suspicious of any web link containing an "@" symbol before the path.',
  },
  {
    vector: 'attachments',
    vectorTitle: 'Email Attachments',
    scenarioTitle: 'Locked Archive in Inbox',
    prompt: 'Why do scam emails attach a password-protected .zip file and write "Password: 1234" right inside the email?',
    artifact: 'Subject: HR Bonus Schedule · File: Bonus_2026.zip (Password: 1234)',
    options: [
      { id: 'a', label: 'To comply with corporate HR privacy standards', isCorrect: false },
      { id: 'b', label: 'To stop automated email antivirus scanners from inspecting what is inside', isCorrect: true },
      { id: 'c', label: 'To reduce the file size for mobile users', isCorrect: false },
    ],
    explanation: 'Encrypted ZIPs lock out automated mail security scanners while giving the human victim the key to unpack the malicious payload manually.',
    takeaway: 'Rule: Treat unsolicited password-locked archives—even with the password included—as high risk.',
  },
  {
    vector: 'messages',
    vectorTitle: 'Messages',
    scenarioTitle: 'Small Delivery Fee Text',
    prompt: 'You get an SMS saying a courier needs $1.99 redelivery fee via a link. You are actually expecting a parcel. What is the safest move?',
    artifact: 'DHL Notice: Parcel held. Pay $1.99 customs balance today at dhl-parcel-pay.top',
    options: [
      { id: 'a', label: 'Pay the $1.99 with a debit card since it is a tiny amount', isCorrect: false },
      { id: 'b', label: 'Check your tracking number directly on the merchant or official courier site', isCorrect: true },
      { id: 'c', label: 'Reply "INFO" to the text to verify the tracking number', isCorrect: false },
    ],
    explanation: 'Scammers only ask for $1.99 so it feels harmless—the real goal is harvesting your card number, CVV, and billing address on a fake form.',
    takeaway: 'Rule: Never enter card details from an SMS link; check tracking independently.',
  },
];

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function scrollToSection(targetId, focusId) {
  const el = document.getElementById(targetId);
  if (!el) return;
  el.scrollIntoView({ behavior: 'smooth' });
  if (focusId) {
    const inputEl = document.getElementById(focusId);
    if (inputEl && !inputEl.closest('.hidden')) {
      setTimeout(() => {
        inputEl.focus({ preventScroll: true });
      }, 450);
    }
  }
}

// 1. Wire all smooth-scroll buttons
document.querySelectorAll('.js-scroll-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    const target = btn.getAttribute('data-target');
    const focus = btn.getAttribute('data-focus');
    if (target) scrollToSection(target, focus);
  });
});

// 2. Subtle scroll-reveal observer for the 4 boxes
const revealItems = document.querySelectorAll('.reveal');
if ('IntersectionObserver' in window) {
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.15 }
  );
  revealItems.forEach((el) => observer.observe(el));
} else {
  revealItems.forEach((el) => el.classList.add('is-visible'));
}

// 3. Single-message Analyzer Logic for Messages, URLs, and Attachments
function riskLabelFor(level) {
  if (level === 'critical') return 'Critical Risk';
  if (level === 'high') return 'High Risk';
  if (level === 'caution') return 'Suspicious Signals';
  return 'Low Risk';
}

function buildHighlightedHtml(text, spans) {
  if (!spans || spans.length === 0) {
    return `<div class="highlighted-box">${escapeHtml(text)}</div>`;
  }
  let html = '';
  let cursor = 0;
  spans.forEach((span, idx) => {
    if (span.start > cursor) {
      html += escapeHtml(text.slice(cursor, span.start));
    }
    const tokenText = escapeHtml(text.slice(span.start, span.end));
    const cls = span.severity === 'danger' ? 'danger' : 'warn';
    html += `<button type="button" class="hl-token ${cls}" data-span-index="${idx}" title="${escapeHtml(span.category)}: ${escapeHtml(span.reason)}">${tokenText}</button>`;
    cursor = span.end;
  });
  if (cursor < text.length) {
    html += escapeHtml(text.slice(cursor));
  }
  return `
    <div class="highlighted-box">${html}</div>
    <div class="js-hl-callout-slot">
      <p class="hl-hint">Click any highlighted word or link above to see why it triggered.</p>
    </div>
  `;
}

function renderAnalysisResult(panel, result) {
  const resultView = panel.querySelector('.js-result-view');
  const riskClass = `risk-${result.riskLevel}`;
  const barWidth = Math.max(6, result.riskScore);

  const rulesHtml =
    result.flags.length > 0
      ? `
      <div>
        <p class="sub-label">Why This Looks Suspicious</p>
        <div class="rules-list">
          ${result.flags
            .map(
              (f, i) => `
              <div class="rule-item">
                <div class="rule-item-top">
                  <span class="rule-item-title">${i + 1}. ${escapeHtml(f.title)}</span>
                  <span class="rule-item-pts ${f.severity}">+${f.points} pts · ${escapeHtml(f.category)}</span>
                </div>
                <p class="rule-item-detail">${escapeHtml(f.detail)}</p>
                ${
                  f.matchedTerms && f.matchedTerms.length > 0
                    ? `<p class="rule-item-terms">Flagged words: ${f.matchedTerms.map((t) => `"${escapeHtml(t)}"`).join(', ')}</p>`
                    : ''
                }
              </div>
            `
            )
            .join('')}
        </div>
      </div>`
      : '';

  const stepsHtml = result.safeSteps
    .map(
      (step) => `
      <li>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
          <path d="m9 11 3 3L22 4" />
        </svg>
        <span>${escapeHtml(step)}</span>
      </li>`
    )
    .join('');

  const followUpsHtml = result.followUps
    .map(
      (item, idx) =>
        `<button type="button" class="btn-followup js-followup-btn" data-fu-index="${idx}">${escapeHtml(item.label)}</button>`
    )
    .join('');

  resultView.innerHTML = `
    <div class="result-stack">
      <div class="user-bubble-wrap">
        <div class="user-bubble">
          <p class="user-bubble-label">Your input</p>
          <p class="user-bubble-text">${escapeHtml(result.input)}</p>
        </div>
      </div>

      <div class="analysis-card ${riskClass}">
        <div>
          <div class="risk-top-row">
            <span class="risk-label">${riskLabelFor(result.riskLevel)}</span>
            <span class="risk-score-text">Risk Score: ${result.riskScore} / 100</span>
          </div>
          <div class="risk-bar-track">
            <div class="risk-bar-fill" style="width: ${barWidth}%"></div>
          </div>
          <h4 class="verdict-title">${escapeHtml(result.verdictTitle)}</h4>
          <p class="working-summary">${escapeHtml(result.workingSummary)}</p>
        </div>

        <div>
          <p class="sub-label">Highlighted Text</p>
          ${buildHighlightedHtml(result.input, result.spans)}
        </div>

        ${rulesHtml}

        <div class="steps-section">
          <p class="sub-label green">Safe Next Steps</p>
          <ul class="steps-list">${stepsHtml}</ul>
        </div>

        <div class="followups-section">
          <p class="sub-label">Already interacted?</p>
          <div class="followups-row">${followUpsHtml}</div>
          <div class="js-followup-slot"></div>
        </div>
      </div>

      <div class="another-row">
        <button type="button" class="btn-primary js-another-btn">Analyze Another</button>
      </div>
    </div>
  `;

  // Wire highlighted span click handlers
  let activeSpanIdx = null;
  const calloutSlot = resultView.querySelector('.js-hl-callout-slot');
  resultView.querySelectorAll('.hl-token').forEach((tok) => {
    tok.addEventListener('click', () => {
      const idx = Number(tok.getAttribute('data-span-index'));
      resultView.querySelectorAll('.hl-token').forEach((t) => t.classList.remove('active'));
      if (activeSpanIdx === idx) {
        activeSpanIdx = null;
        calloutSlot.innerHTML = '<p class="hl-hint">Click any highlighted word or link above to see why it triggered.</p>';
        return;
      }
      activeSpanIdx = idx;
      tok.classList.add('active');
      const span = result.spans[idx];
      calloutSlot.innerHTML = `
        <div class="hl-callout">
          <span><strong>${escapeHtml(span.category)}:</strong> ${escapeHtml(span.reason)}</span>
          <button type="button" class="hl-dismiss">Dismiss</button>
        </div>
      `;
      calloutSlot.querySelector('.hl-dismiss').addEventListener('click', () => {
        activeSpanIdx = null;
        tok.classList.remove('active');
        calloutSlot.innerHTML = '<p class="hl-hint">Click any highlighted word or link above to see why it triggered.</p>';
      });
    });
  });

  // Wire follow-up playbook toggles
  let activeFollowUpIdx = null;
  const fuSlot = resultView.querySelector('.js-followup-slot');
  resultView.querySelectorAll('.js-followup-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const idx = Number(btn.getAttribute('data-fu-index'));
      resultView.querySelectorAll('.js-followup-btn').forEach((b) => b.classList.remove('active'));
      if (activeFollowUpIdx === idx) {
        activeFollowUpIdx = null;
        fuSlot.innerHTML = '';
        return;
      }
      activeFollowUpIdx = idx;
      btn.classList.add('active');
      const pb = result.followUps[idx];
      fuSlot.innerHTML = `
        <div class="followup-box">
          <p class="followup-title">${escapeHtml(pb.title)}</p>
          <ol class="followup-steps">
            ${pb.steps
              .map(
                (s, i) => `<li><span class="followup-num">0${i + 1}.</span><span>${escapeHtml(s)}</span></li>`
              )
              .join('')}
          </ol>
        </div>
      `;
    });
  });

  // Wire bottom "Analyze Another" reset button
  const vector = panel.getAttribute('data-panel');
  resultView.querySelector('.js-another-btn').addEventListener('click', () => resetPanel(vector));
}

function resetPanel(vector) {
  const panel = document.querySelector(`.workspace-panel[data-panel="${vector}"]`);
  const refreshBtn = document.querySelector(`.js-refresh-btn[data-vector="${vector}"]`);
  const inputView = panel.querySelector('.js-input-view');
  const resultView = panel.querySelector('.js-result-view');
  const textarea = panel.querySelector('textarea');
  const submitBtn = panel.querySelector('.btn-analyze');

  resultView.innerHTML = '';
  resultView.classList.add('hidden');
  inputView.classList.remove('hidden');
  if (refreshBtn) refreshBtn.classList.add('hidden');

  textarea.value = '';
  submitBtn.disabled = true;
  textarea.focus({ preventScroll: true });
}

document.querySelectorAll('.js-analyze-form').forEach((form) => {
  const vector = form.getAttribute('data-vector');
  const panel = form.closest('.workspace-panel');
  const textarea = form.querySelector('textarea');
  const submitBtn = form.querySelector('.btn-analyze');
  const inputView = panel.querySelector('.js-input-view');
  const resultView = panel.querySelector('.js-result-view');
  const refreshBtn = document.querySelector(`.js-refresh-btn[data-vector="${vector}"]`);

  textarea.addEventListener('input', () => {
    submitBtn.disabled = !textarea.value.trim();
  });

  textarea.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (textarea.value.trim()) form.requestSubmit();
    }
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = textarea.value.trim();
    if (!text) return;

    inputView.classList.add('hidden');
    resultView.classList.remove('hidden');
    if (refreshBtn) refreshBtn.classList.remove('hidden');

    resultView.innerHTML = `
      <div class="result-stack">
        <div class="user-bubble-wrap">
          <div class="user-bubble">
            <p class="user-bubble-label">Your input</p>
            <p class="user-bubble-text">${escapeHtml(text)}</p>
          </div>
        </div>
        <div class="loading-row">Analyzing...</div>
      </div>
    `;

    try {
      const res = await fetch(`${API_BASE_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vector, input: text }),
      });
      if (!res.ok) throw new Error('Server error');
      const data = await res.json();
      renderAnalysisResult(panel, data);
    } catch {
      resultView.innerHTML = `
        <div class="result-stack">
          <p class="working-summary">Could not reach the analysis server. Please refresh and try again.</p>
          <div class="another-row">
            <button type="button" class="btn-primary js-err-reset">Try Again</button>
          </div>
        </div>
      `;
      resultView.querySelector('.js-err-reset').addEventListener('click', () => resetPanel(vector));
    }
  });
});

document.querySelectorAll('.js-refresh-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    resetPanel(btn.getAttribute('data-vector'));
  });
});

// 4. Awareness Quiz Logic
let quizIndex = 0;
let quizScore = 0;
let quizAnsweredId = null;
let quizDone = false;

const quizContainer = document.getElementById('quiz-container');
const quizProgress = document.getElementById('quiz-progress');

function renderQuiz() {
  if (quizDone) {
    quizProgress.textContent = 'Completed';
    const summaryText =
      quizScore >= 5
        ? 'Great eye for red flags. Always pause and verify before clicking links or sharing codes.'
        : 'Good practice run. Whenever a message feels urgent or asks for codes or fees, check it first.';
    quizContainer.innerHTML = `
      <p class="quiz-vector" style="margin:0 0 8px;font-size:0.875rem;">Quiz Complete</p>
      <h4 class="quiz-prompt" style="font-size:1.6rem;">You scored ${quizScore} out of ${QUIZ_QUESTIONS.length}</h4>
      <p class="quiz-explanation">${escapeHtml(summaryText)}</p>
      <div style="display:flex;flex-wrap:wrap;gap:12px;margin-top:20px;">
        <button type="button" class="btn-primary" id="quiz-retake">Retake Quiz</button>
        <button type="button" class="btn-secondary" id="quiz-back">Back to Options</button>
      </div>
    `;
    document.getElementById('quiz-retake').addEventListener('click', () => {
      quizIndex = 0;
      quizScore = 0;
      quizAnsweredId = null;
      quizDone = false;
      renderQuiz();
    });
    document.getElementById('quiz-back').addEventListener('click', () => scrollToSection('vectors'));
    return;
  }

  const q = QUIZ_QUESTIONS[quizIndex];
  const hasAnswered = quizAnsweredId !== null;
  const chosenOption = q.options.find((o) => o.id === quizAnsweredId);
  quizProgress.textContent = `Question ${quizIndex + 1} of ${QUIZ_QUESTIONS.length} · Score ${quizScore}`;

  const optionsHtml = q.options
    .map((opt) => {
      let cls = '';
      let icon = '';
      if (hasAnswered) {
        if (opt.isCorrect) {
          cls = 'correct';
          icon = '<span style="color:#19FF6E;font-weight:700;">✓</span>';
        } else if (opt.id === quizAnsweredId) {
          cls = 'wrong';
          icon = '<span style="color:#f87171;font-weight:700;">✕</span>';
        } else {
          cls = 'dimmed';
        }
      }
      return `
        <button type="button" class="quiz-option ${cls}" data-opt-id="${opt.id}" ${hasAnswered ? 'disabled' : ''}>
          <span>${escapeHtml(opt.label)}</span>
          ${icon}
        </button>
      `;
    })
    .join('');

  const feedbackHtml = hasAnswered
    ? `
      <div class="quiz-feedback">
        <p class="quiz-feedback-status ${chosenOption && chosenOption.isCorrect ? 'ok' : 'miss'}">
          ${chosenOption && chosenOption.isCorrect ? 'Correct.' : 'Not quite — here is why:'}
        </p>
        <p class="quiz-explanation">${escapeHtml(q.explanation)}</p>
        <p class="quiz-takeaway">${escapeHtml(q.takeaway)}</p>
        <div class="quiz-actions-row">
          <button type="button" class="btn-link-subtle" id="quiz-jump-inspector">
            Try ${escapeHtml(q.vectorTitle)} Inspector ↑
          </button>
          <button type="button" class="btn-primary" id="quiz-next-btn">
            ${quizIndex + 1 < QUIZ_QUESTIONS.length ? 'Next Question' : 'Finish Quiz'}
          </button>
        </div>
      </div>
    `
    : '';

  quizContainer.innerHTML = `
    <div class="quiz-meta">
      <span class="quiz-vector">${escapeHtml(q.vectorTitle)}</span>
      <span aria-hidden="true">·</span>
      <span>${escapeHtml(q.scenarioTitle)}</span>
    </div>
    <h4 class="quiz-prompt">${escapeHtml(q.prompt)}</h4>
    <div class="quiz-artifact">${escapeHtml(q.artifact)}</div>
    <div class="quiz-options">${optionsHtml}</div>
    ${feedbackHtml}
  `;

  if (!hasAnswered) {
    quizContainer.querySelectorAll('.quiz-option').forEach((btn) => {
      btn.addEventListener('click', () => {
        quizAnsweredId = btn.getAttribute('data-opt-id');
        const picked = q.options.find((o) => o.id === quizAnsweredId);
        if (picked && picked.isCorrect) quizScore += 1;
        renderQuiz();
      });
    });
  } else {
    document.getElementById('quiz-next-btn').addEventListener('click', () => {
      if (quizIndex + 1 < QUIZ_QUESTIONS.length) {
        quizIndex += 1;
        quizAnsweredId = null;
      } else {
        quizDone = true;
      }
      renderQuiz();
    });
    document.getElementById('quiz-jump-inspector').addEventListener('click', () => {
      scrollToSection(`section-${q.vector}`, `input-${q.vector}`);
    });
  }
}

renderQuiz();
