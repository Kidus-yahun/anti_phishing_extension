"""
Head-to-Head Accuracy & Latency Benchmark:
Current PhishShield Model (Scikit-Learn TF-IDF) vs Laya System-1 Decision Engine
"""

import sys
import os
import time

os.environ["HF_HUB_DISABLE_SYMLINKS"] = "1"
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import pickle
import laya

TEST_CORPUS = [
    # 1. Classic Brand Phishing
    {
        "text": "URGENT: Your PayPal account has been suspended due to unauthorized login. Click here to verify credentials within 24 hours.",
        "label": "PHISHING"
    },
    # 2. Executive Impersonation / BEC
    {
        "text": "I am in an executive board meeting and cannot take calls. Please process an urgent wire transfer of $4,500 to our new vendor right now.",
        "label": "PHISHING"
    },
    # 3. IT Helpdesk Password Reset Trap
    {
        "text": "IT Support Notice: Mandatory system migration scheduled tonight. Re-enter your employee login and password to prevent account termination.",
        "label": "PHISHING"
    },
    # 4. Multilingual Phishing (Spanish)
    {
        "text": "Alerta de Seguridad: Su cuenta bancaria ha sido bloqueada. Ingrese su contrasena y tarjeta inmediatamente para restablecer el acceso.",
        "label": "PHISHING"
    },
    # 5. Multilingual Phishing (French)
    {
        "text": "Votre colis n'a pas pu etre livre. Veuillez payer les frais de livraison de 2,99 euros sous 24 heures pour eviter le retour.",
        "label": "PHISHING"
    },
    # 6. Corporate Ham (Legitimate)
    {
        "text": "Hi Team, thanks for attending this morning's weekly sync call. Attached are the meeting notes and project milestones for the upcoming release.",
        "label": "LEGITIMATE"
    },
    # 7. Routine Personal/Transaction Ham
    {
        "text": "Your electric utility bill for September is now available online. Log in to your portal whenever convenient to view your balance.",
        "label": "LEGITIMATE"
    },
    # 8. Friendly Slack / Email message
    {
        "text": "Hey Alex, are we still meeting for lunch today at 12:30 PM? Let me know if that time works for you.",
        "label": "LEGITIMATE"
    }
]

def run_head_to_head():
    print("=" * 75)
    print("🥊 HEAD-TO-HEAD BENCHMARK: Current PhishShield Model vs Laya System-1")
    print("=" * 75)

    # 1. Load Current Model (Scikit-Learn TF-IDF + LogisticRegression)
    model_path = "app/models/phishing_model.pkl"
    with open(model_path, "rb") as f:
        data = pickle.load(f)
    vectorizer = data["vectorizer"]
    classifier = data["classifier"]

    # 2. Load Laya Agent
    print("[*] Loading Laya System-1 Agent...")
    laya_agent = laya.load("convaiinnovations/laya")
    
    # 1-question fast triage for < 1s browser detection
    fast_phish_question = {
        "is_phishing": {
            "type": "noul",
            "instructions": "Is this text a phishing attempt, social engineering attack, or fraud?",
            "criteria": {
                "true": "phishing attack, scam, or credential theft",
                "false": "legitimate, normal, or safe message"
            }
        }
    }
    # Warmup
    laya_agent.decide("Warmup test message", questions=fast_phish_question)

    print("\n[+] Benchmark running across 8 diverse test cases...\n")

    current_correct = 0
    laya_correct = 0
    current_latencies = []
    laya_latencies = []

    print(f"{'#':<3} | {'Expected':<11} | {'Current Model (TF-IDF)':<25} | {'Laya System-1':<25}")
    print("-" * 75)

    for idx, sample in enumerate(TEST_CORPUS, 1):
        text = sample["text"]
        expected = sample["label"]

        # --- Benchmark Current Model ---
        t0 = time.perf_counter()
        feat = vectorizer.transform([text])
        prob = classifier.predict_proba(feat)[0][1]
        cur_time_ms = (time.perf_counter() - t0) * 1000
        current_latencies.append(cur_time_ms)
        cur_pred = "PHISHING" if prob >= 0.50 else "LEGITIMATE"
        if cur_pred == expected:
            current_correct += 1

        # --- Benchmark Laya Model ---
        t1 = time.perf_counter()
        # Truncate to first 500 chars to guarantee sub-second execution
        dec = laya_agent.decide(text[:500], questions=fast_phish_question)
        laya_time_ms = (time.perf_counter() - t1) * 1000
        laya_latencies.append(laya_time_ms)
        
        phish_info = dec["is_phishing"]
        laya_score = phish_info.get("noul", 0.0)
        laya_pred = "PHISHING" if laya_score >= 0.50 else "LEGITIMATE"
        if laya_pred == expected:
            laya_correct += 1

        cur_str = f"{cur_pred} ({prob:.0%}, {cur_time_ms:.1f}ms)"
        laya_str = f"{laya_pred} ({laya_score:.0%}, {laya_time_ms:.1f}ms)"

        cur_mark = "✅" if cur_pred == expected else "❌"
        laya_mark = "✅" if laya_pred == expected else "❌"

        print(f"{idx:<3} | {expected:<11} | {cur_mark} {cur_str:<23} | {laya_mark} {laya_str:<23}")

    print("\n" + "=" * 75)
    print("📊 FINAL BENCHMARK COMPARISON SUMMARY:")
    print("=" * 75)
    print(f"Accuracy:")
    print(f"   • Current Model (TF-IDF + LogReg) : {current_correct}/{len(TEST_CORPUS)} ({current_correct/len(TEST_CORPUS):.1%})")
    print(f"   • Laya System-1 Decision Engine   : {laya_correct}/{len(TEST_CORPUS)} ({laya_correct/len(TEST_CORPUS):.1%})")
    print(f"\nLatency on CPU:")
    print(f"   • Current Model Average Latency   : {sum(current_latencies)/len(current_latencies):.2f} ms")
    print(f"   • Laya Average Latency            : {sum(laya_latencies)/len(laya_latencies):.1f} ms  (Target: < 1000 ms)")
    print("=" * 75)

if __name__ == "__main__":
    run_head_to_head()
