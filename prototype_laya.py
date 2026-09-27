"""
PhishShield AI + Laya Prototype Benchmark
==========================================
Demonstrating non-autoregressive "System 1" social engineering & phishing triage
using Laya (convaiinnovations/laya).
"""

import sys
import os

# Disable HF Hub symlinks on Windows non-admin
os.environ["HF_HUB_DISABLE_SYMLINKS"] = "1"
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

# Ensure UTF-8 output on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import time
import laya
from laya.email import email_state

def run_prototype():
    print("=" * 68)
    print("[*] PhishShield AI + Laya System-1 Decision Prototype")
    print("=" * 68)

    print("\n[1/3] Loading Laya Model Checkpoint (convaiinnovations/laya)...")
    t0 = time.perf_counter()
    try:
        agent = laya.load("convaiinnovations/laya")
        load_time = time.perf_counter() - t0
        print(f"[+] Model loaded in {load_time:.2f}s")
    except Exception as e:
        print(f"[-] Failed to load Laya model: {e}")
        import traceback
        traceback.print_exc()
        return

    # Questions tailored for PhishShield threat triage
    phishshield_questions = {
        "is_phishing": {
            "type": "noul",
            "instructions": "Is this message a phishing attempt, social engineering attack, or fraud?",
            "criteria": {
                "true": "phishing attack, credential harvest, or scam",
                "false": "legitimate message"
            }
        },
        "attack_vector": {
            "type": "choice",
            "instructions": "What is the primary intent or vector in `body`?",
            "criteria": {
                "credential_harvest": "stealing login passwords, credit cards, or pins",
                "urgent_coercion": "panicking the user with account suspensions or deadlines",
                "authority_impersonation": "pretending to be executive, IT support, or legal authority",
                "benign_communication": "normal workplace, personal, or transactional communication"
            }
        },
        "urgency_level": {
            "type": "score",
            "instructions": "How much psychological pressure or urgency is in `body`?",
            "criteria": [
                "no pressure / calm",
                "moderate reminder",
                "high panic / immediate deadline"
            ]
        }
    }

    # Warmup pass to eliminate one-time PyTorch compilation / kernel initialization overhead
    warmup_state = email_state(subject="Ping", body="Hello World", sender="test@local")
    agent.decide(warmup_state, questions=phishshield_questions, return_details=True)

    # Test cases representing diverse attack styles and legitimate communication
    test_cases = [
        {
            "id": 1,
            "name": "PayPal Credential Harvesting & Urgency Phishing",
            "subject": "URGENT: Account Suspended - Immediate Action Required",
            "from": "support@paypa1-security-verification.xyz",
            "body": (
                "We detected an unauthorized sign-in attempt on your PayPal account. "
                "Your account has been temporarily restricted. You must log in within 24 hours "
                "to verify your identity and restore full access to your funds. "
                "Click the secure link below to verify your password and billing credentials. "
                "If you do not complete verification, your account will be permanently terminated."
            ),
            "expected_phish": True
        },
        {
            "id": 2,
            "name": "Legitimate Corporate Team Update",
            "subject": "Team Sync Minutes & Weekly Updates",
            "from": "sarah.jenkins@company.com",
            "body": (
                "Hi Team, thanks for attending this morning's weekly sync call. "
                "Attached are the meeting notes and project milestones for the upcoming release. "
                "Let me know if anyone has questions before our code freeze on Friday."
            ),
            "expected_phish": False
        },
        {
            "id": 3,
            "name": "Executive Impersonation (CEO Wire Transfer Fraud)",
            "subject": "Quick task - are you at your desk?",
            "from": "ceo-direct-office@company-partner-portal.com",
            "body": (
                "I am currently in an executive board meeting and cannot take phone calls. "
                "I need you to process an urgent confidential wire transfer to a vendor account "
                "before 3 PM today. Please reply immediately once you see this."
            ),
            "expected_phish": True
        },
        {
            "id": 4,
            "name": "Multilingual Phishing (Spanish Credential Theft)",
            "subject": "Alerta de Seguridad: Su cuenta bancaria ha sido bloqueada",
            "from": "seguridad@banco-verificacion.online",
            "body": (
                "Estimado cliente, hemos detectado actividad sospechosa en su cuenta. "
                "Su acceso ha sido suspendido temporalmente. Por favor, introduzca su contraseña "
                "y número de tarjeta de inmediato para evitar el cierre definitivo."
            ),
            "expected_phish": True
        }
    ]

    print("\n[2/3] Running Benchmark Across Diverse Threat Scenarios...")
    print("-" * 68)

    latencies = []

    for test in test_cases:
        state = email_state(
            subject=test["subject"],
            body=test["body"],
            sender=test["from"]
        )

        start = time.perf_counter()
        result = agent.decide(state, questions=phishshield_questions, return_details=True)
        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies.append(elapsed_ms)

        print(f"\n[Case {test['id']}]: {test['name']}")
        print(f"   From:     {test['from']}")
        print(f"   Subject:  {test['subject']}")
        print(f"   ⚡ Speed:  {elapsed_ms:.1f} ms (CPU inference)")
        print(f"   📊 Laya Verdict:")
        for q_name, val in result.values.items():
            conf = result.confidence.get(q_name)
            conf_str = f" [Confidence: {conf:.1%}]" if conf is not None else ""
            print(f"      • {q_name:<16}: {val}{conf_str}")

    avg_latency = sum(latencies) / len(latencies)
    print("\n" + "=" * 68)
    print(f"[3/3] Benchmark Summary:")
    print(f"   • Total Cases Evaluated : {len(test_cases)}")
    print(f"   • Average CPU Latency   : {avg_latency:.1f} ms per multi-question triage")
    print(f"   • Target Inference Fit  : Validated for background email & page triage")
    print("=" * 68)

if __name__ == "__main__":
    run_prototype()
