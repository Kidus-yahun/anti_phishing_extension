"""
PhishShield AI - RoBERTa Fine-Tuning & Evaluation Script
Fine-tunes a RoBERTa sequence classification transformer on phishing vs legitimate datasets.
"""

import os
import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments
)

# Training corpus representing diverse phishing tactics and benign communications
DATASET = [
    # Phishing / Social Engineering (Label 1)
    ("URGENT: Your account has been temporarily suspended due to unauthorized access. Please verify credentials immediately.", 1),
    ("Security Alert: Someone attempted to log into your account from an unknown device. Update your password now.", 1),
    ("Action Required: Your online banking session was locked. Re-enter your credentials to restore service.", 1),
    ("Notice: Your refund of $1,250 is pending. Click the link to claim your reward via direct deposit.", 1),
    ("Helpdesk Notice: Mandatory system migration required. Verify your email credentials or your inbox will be terminated.", 1),
    ("Kindly review the urgent invoice attached and process the payment to the vendor right away.", 1),
    ("Your package delivery failed. Pay the outstanding delivery fee to prevent return to sender.", 1),
    ("Unusual activity detected on your PayPal account. Confirm identity to avoid suspension.", 1),
    ("IRS Tax Notification: You are eligible for a tax rebate. Submit your banking details.", 1),
    ("HR Announcement: Please review the updated bonus policy and sign in with your corporate account.", 1),

    # Legitimate / Ham (Label 0)
    ("Hi team, here is the weekly project status report attached for your review. Let me know if you have questions.", 0),
    ("Your monthly electricity statement is now available online. Log in to your utility portal to view the details.", 0),
    ("Hey Alex, are we still meeting for lunch today at 12:30 PM?", 0),
    ("Thank you for your recent purchase. Your receipt and tracking number are included below.", 0),
    ("Reminder: Team sync call scheduled tomorrow at 10:00 AM via Google Meet.", 0),
    ("Here is the updated documentation for the API endpoints we discussed yesterday.", 0),
    ("Your flight reservation is confirmed. Have a pleasant flight.", 0),
    ("The code pull request has been approved and merged into the main branch.", 0),
    ("Please find attached the minutes from this morning's planning meeting.", 0),
    ("Happy birthday! Wishing you a fantastic day ahead.", 0)
]

class PhishingDataset(torch.utils.data.Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx])
        return item

    def __len__(self):
        return len(self.labels)

def train_roberta(model_name: str = "distilroberta-base", output_dir: str = "app/models/roberta_phishing"):
    print(f"[RoBERTa Pipeline] Loading tokenizer and base model: {model_name}...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)

    texts = [item[0] for item in DATASET]
    labels = [item[1] for item in DATASET]

    print("[RoBERTa Pipeline] Tokenizing dataset...")
    encodings = tokenizer(texts, truncation=True, padding=True, max_length=128)
    train_dataset = PhishingDataset(encodings, labels)

    os.makedirs(output_dir, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=3,
        per_device_train_batch_size=4,
        warmup_steps=10,
        weight_decay=0.01,
        logging_steps=5,
        save_strategy="no",
        use_cpu=True
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset
    )

    print("[RoBERTa Pipeline] Training RoBERTa model...")
    trainer.train()

    print(f"[RoBERTa Pipeline] Saving fine-tuned model and tokenizer to: {output_dir}")
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    print("[RoBERTa Pipeline] Training complete! RoBERTa weights are ready.")

if __name__ == "__main__":
    train_roberta()
