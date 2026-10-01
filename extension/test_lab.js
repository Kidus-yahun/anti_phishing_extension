/**
 * PhishShield AI - Interactive Test Lab Controller
 * Manifest V3 CSP Compliant: zero inline scripts, zero inline event handlers.
 *
 * Features:
 *   - Multiple dynamic injection scenarios (chat, email, SMS, social DM)
 *   - Detection speed timer — measures time from DOM injection to badge appearance
 *   - Rotating message content for each scenario type
 */

document.addEventListener("DOMContentLoaded", () => {

  // ── Detection Speed Timer ─────────────────────────────────────────────────
  function measureDetectionSpeed(injectedElement) {
    const readout = document.getElementById("speed-readout");
    const speedVal = document.getElementById("speed-value");
    if (!readout || !speedVal) return;

    readout.style.display = "block";
    speedVal.textContent = "Scanning…";
    speedVal.style.color = "#fbbf24";

    const t0 = performance.now();
    let resolved = false;

    // Watch for PhishShield badge or flagged-link class appearing
    const observer = new MutationObserver(() => {
      const badge = injectedElement.querySelector(".phishshield-inline-badge");
      const flagged = injectedElement.querySelector(".phishshield-flagged-link");
      if ((badge || flagged) && !resolved) {
        resolved = true;
        observer.disconnect();
        const elapsed = (performance.now() - t0).toFixed(0);
        speedVal.textContent = elapsed + " ms";
        speedVal.style.color = elapsed < 500 ? "#34d399" : elapsed < 1500 ? "#fbbf24" : "#f87171";
      }
    });

    observer.observe(injectedElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] });

    // Timeout after 8 seconds
    setTimeout(() => {
      if (!resolved) {
        resolved = true;
        observer.disconnect();
        speedVal.textContent = "No detection (timeout)";
        speedVal.style.color = "#f87171";
      }
    }, 8000);
  }

  // ── Injection Helpers ─────────────────────────────────────────────────────
  function getArea() {
    return document.getElementById("dynamic-injection-area");
  }

  function createRow(borderColor) {
    const row = document.createElement("div");
    row.className = "link-row";
    row.style.borderLeft = "3px solid " + borderColor;
    return row;
  }

  // ── 1. Chat Phishing Messages (Rotating) ──────────────────────────────────
  const chatScenarios = [
    {
      label: "[Incoming Urgent Direct Message]",
      body: "Hey, your account security was compromised! Confirm your login here:",
      url: "http://discord-gift-nitro-claim.xyz/verify",
      text: "http://discord-gift-nitro-claim.xyz/verify"
    },
    {
      label: "[New Message from Admin]",
      body: "⚠️ Your Discord Nitro subscription expired. Renew free for 3 months:",
      url: "http://disc0rd-nitro-renewal.click/free",
      text: "Renew Nitro for Free"
    },
    {
      label: "[Urgent from HR Bot]",
      body: "Mandatory: Update your Slack workspace credentials before midnight or lose access:",
      url: "http://slack-workspace-verify.top/auth",
      text: "http://slack-workspace-verify.top/auth"
    },
    {
      label: "[WhatsApp Security Alert]",
      body: "Someone tried to register your phone number on another device. Verify immediately:",
      url: "http://whatsapp-verify-number.xyz/confirm",
      text: "Verify your WhatsApp number"
    }
  ];
  let chatIndex = 0;

  const btnChat = document.getElementById("btn-inject-chat");
  if (btnChat) {
    btnChat.addEventListener("click", () => {
      const area = getArea();
      if (!area) return;

      const scenario = chatScenarios[chatIndex % chatScenarios.length];
      chatIndex++;

      const msg = createRow("#ef4444");
      msg.innerHTML = [
        '<div style="display: flex; justify-content: space-between; align-items: center;">',
        '  <span class="link-label" style="color: #f87171;">' + scenario.label + '</span>',
        '  <span style="font-size: 10px; color: #64748b;">Just now</span>',
        '</div>',
        '<p style="font-size: 12px; color: #cbd5e1;">' + scenario.body + '</p>',
        '<a href="' + scenario.url + '">' + scenario.text + '</a>'
      ].join("\n");

      area.prepend(msg);
      measureDetectionSpeed(msg);
    });
  }

  // ── 2. Email Phishing Messages (Rotating) ─────────────────────────────────
  const emailScenarios = [
    {
      subject: "URGENT: Your Amazon account has been locked",
      from: "Amazon Security &lt;noreply@amaz0n-security.club&gt;",
      body: "We detected suspicious login attempts on your Amazon account from an unrecognized device in <strong>Lagos, Nigeria</strong>. Your account has been temporarily locked for protection.<br><br>You must verify your identity within <strong>12 hours</strong> to restore access:",
      url: "http://amaz0n-account-recovery.club/verify",
      text: "Verify Your Amazon Account"
    },
    {
      subject: "Invoice #INV-29847 — Payment Overdue",
      from: "Accounts Receivable &lt;billing@paypa1-invoices.xyz&gt;",
      body: "This is a final reminder that Invoice #INV-29847 for <strong>$892.50</strong> is now 7 days past due. Immediate payment is required to avoid a <strong>$50 late fee</strong> and service interruption.<br><br>Pay now to avoid penalties:",
      url: "http://paypa1-invoice-payment.xyz/pay-now",
      text: "Pay Invoice Now — Avoid Late Fee"
    },
    {
      subject: "Your Dropbox storage is 98% full",
      from: "Dropbox &lt;alerts@dr0pbox-storage.top&gt;",
      body: "Your Dropbox account has reached <strong>98% capacity</strong>. File syncing has been paused. Upgrade to Pro for free (limited time) or download your files before they are permanently deleted in <strong>48 hours</strong>:",
      url: "http://dr0pbox-upgrade-storage.top/free-pro",
      text: "https://www.dropbox.com/upgrade-storage"
    }
  ];
  let emailIndex = 0;

  const btnEmail = document.getElementById("btn-inject-email");
  if (btnEmail) {
    btnEmail.addEventListener("click", () => {
      const area = getArea();
      if (!area) return;

      const s = emailScenarios[emailIndex % emailScenarios.length];
      emailIndex++;

      const msg = createRow("#a855f7");
      msg.innerHTML = [
        '<span class="link-label" style="color: #c084fc;">📧 Incoming Phishing Email</span>',
        '<div style="font-size: 11px; color: #64748b; margin-bottom: 4px;">From: ' + s.from + '</div>',
        '<div style="font-size: 13px; font-weight: 700; color: #f87171; margin-bottom: 6px;">Subject: ' + s.subject + '</div>',
        '<div style="font-size: 12px; color: #cbd5e1; line-height: 1.6;">' + s.body + '</div>',
        '<a href="' + s.url + '" style="margin-top: 6px; display: inline-block;">' + s.text + '</a>'
      ].join("\n");

      area.prepend(msg);
      measureDetectionSpeed(msg);
    });
  }

  // ── 3. SMS Smishing Messages (Rotating) ───────────────────────────────────
  const smsScenarios = [
    {
      body: "USPS: Your package #9420-1148 could not be delivered. Reschedule delivery here:",
      url: "http://usps-redelivery-schedule.top/track",
      text: "http://usps-redelivery-schedule.top/track"
    },
    {
      body: "IRS ALERT: You have an outstanding tax refund of $1,247.00. Claim before Oct 15:",
      url: "http://irs-tax-refund-claim.xyz/claim",
      text: "http://irs-tax-refund-claim.xyz/claim"
    },
    {
      body: "Your bank account has been debited $299.99 for Apple iCloud+. If this wasn't you, dispute here:",
      url: "http://apple-billing-dispute.click/refund",
      text: "Dispute this charge"
    }
  ];
  let smsIndex = 0;

  const btnSms = document.getElementById("btn-inject-sms");
  if (btnSms) {
    btnSms.addEventListener("click", () => {
      const area = getArea();
      if (!area) return;

      const s = smsScenarios[smsIndex % smsScenarios.length];
      smsIndex++;

      const msg = createRow("#22d3ee");
      msg.innerHTML = [
        '<div style="display: flex; justify-content: space-between; align-items: center;">',
        '  <span class="link-label" style="color: #22d3ee;">📱 Incoming SMS</span>',
        '  <span style="font-size: 10px; color: #64748b;">Just now</span>',
        '</div>',
        '<p style="font-size: 13px; color: #cbd5e1;">' + s.body + '</p>',
        '<a href="' + s.url + '">' + s.text + '</a>'
      ].join("\n");

      area.prepend(msg);
      measureDetectionSpeed(msg);
    });
  }

  // ── 4. Social Media DM Scam (Rotating) ────────────────────────────────────
  const socialScenarios = [
    {
      platform: "Instagram DM",
      sender: "@verified_support_ig",
      body: "🚨 Your Instagram account has been flagged for copyright violation. You have 24 hours to submit an appeal or your account will be permanently disabled:",
      url: "http://instagram-copyright-appeal.click/submit",
      text: "Submit copyright appeal"
    },
    {
      platform: "LinkedIn Message",
      sender: "Recruiter — Sarah K.",
      body: "Hi! I came across your profile and I'm very impressed. We have a Senior DevOps role at Google paying $280k+. Apply through our fast-track portal:",
      url: "http://google-careers-apply.top/fast-track",
      text: "https://careers.google.com/apply"
    },
    {
      platform: "Twitter/X DM",
      sender: "@CryptoAirdrop_Official",
      body: "🎁 EXCLUSIVE: You've been selected for the ETH 2.0 airdrop. Connect your wallet to claim 0.75 ETH ($2,400):",
      url: "http://ethereum-airdrop-claim.xyz/connect-wallet",
      text: "Claim your ETH airdrop now"
    }
  ];
  let socialIndex = 0;

  const btnSocial = document.getElementById("btn-inject-social");
  if (btnSocial) {
    btnSocial.addEventListener("click", () => {
      const area = getArea();
      if (!area) return;

      const s = socialScenarios[socialIndex % socialScenarios.length];
      socialIndex++;

      const msg = createRow("#f59e0b");
      msg.innerHTML = [
        '<div style="display: flex; justify-content: space-between; align-items: center;">',
        '  <span class="link-label" style="color: #fbbf24;">🐦 ' + s.platform + '</span>',
        '  <span style="font-size: 10px; color: #64748b;">From: ' + s.sender + '</span>',
        '</div>',
        '<p style="font-size: 12px; color: #cbd5e1;">' + s.body + '</p>',
        '<a href="' + s.url + '">' + s.text + '</a>'
      ].join("\n");

      area.prepend(msg);
      measureDetectionSpeed(msg);
    });
  }

  // ── 5. Fake Popup Modal ───────────────────────────────────────────────────
  const btnModal = document.getElementById("btn-inject-modal");
  if (btnModal) {
    btnModal.addEventListener("click", () => {
      const existing = document.getElementById("active-mock-modal");
      if (existing) existing.remove();

      const overlay = document.createElement("div");
      overlay.className = "mock-modal-overlay";
      overlay.id = "active-mock-modal";

      overlay.innerHTML = [
        '<div class="mock-modal">',
        '  <div style="font-size: 32px; margin-bottom: 8px;">⚠️</div>',
        '  <h3 style="font-size: 18px; margin-bottom: 8px; color: #ffffff;">Session Expiration Notice</h3>',
        '  <p style="font-size: 13px; color: #94a3b8; margin-bottom: 16px;">',
        '    Your Microsoft Office 365 session has expired. Re-authenticate to avoid losing unsaved document changes.',
        '  </p>',
        '  <div class="link-row" style="text-align: left; margin-bottom: 12px;">',
        '    <a href="http://m1crosoft-office365-login.top/auth">Click here to re-authenticate with Microsoft</a>',
        '  </div>',
        '  <button id="btn-mock-modal-close" class="mock-modal-close">',
        '    Dismiss Test Modal',
        '  </button>',
        '</div>'
      ].join("\n");

      document.body.appendChild(overlay);

      const closeBtn = document.getElementById("btn-mock-modal-close");
      if (closeBtn) {
        closeBtn.addEventListener("click", () => {
          overlay.remove();
        });
      }
    });
  }

  // ── 6. Clear Dynamic Area ─────────────────────────────────────────────────
  const btnClear = document.getElementById("btn-clear");
  if (btnClear) {
    btnClear.addEventListener("click", () => {
      const area = getArea();
      if (area) area.innerHTML = "";

      // Reset speed readout
      const readout = document.getElementById("speed-readout");
      if (readout) readout.style.display = "none";
    });
  }

  // ── 7. Adapt Navigation for Server vs Local File Mode ─────────────────────
  if (window.location.protocol !== "file:") {
    const dashLink = document.getElementById("nav-dashboard-link");
    if (dashLink) {
      dashLink.href = (window.location.protocol === "http:" || window.location.protocol === "https:") ? "/" : "dashboard.html";
    }
  }
});
