# Email Threat Detection Platform (Hybrid Rule-Based + AI/ML Ensemble)
**Computer Networks Course Project — 5th Semester**  
**Vasavi College of Engineering | Batch-2 | Team No: 21**  
**Team Members:** 1602-24-737-164, 1602-24-737-163, 1602-24-737-165  

---

## 📌 Project Overview
The **Email Threat Detection Platform** is a web-based client-server application built with **Python and Flask** that inspects emails for security threats, phishing, and spoofing using a **Hybrid Ensemble Architecture** combining:
1. **Rule-Based Protocol Engine:** Evaluates RFC compliance (SMTP envelope alignment, DNS MX records, SPF/DKIM verification, HTTP vs HTTPS).
2. **AI / ML Machine Learning Model:** Evaluates semantic text patterns using TF-IDF N-grams and a regularized Logistic Regression classifier to calculate phishing probability.
3. **Ensemble Averaging:** Computes the decisive threat score as `Final Score = round((Rule_Score + ML_Score) / 2)` to categorize the final threat level.

The project demonstrates practical application of core Computer Networks concepts:
- **SMTP Protocol (RFC 5321 & RFC 5322):** Header vs Envelope spoofing detection
- **DNS (Domain Name System):** A/AAAA resolution and MX (Mail Exchange) record querying
- **Email Authentication:** SPF (Sender Policy Framework), DKIM, and DMARC verification
- **Network Routing:** Tracing multi-hop Mail Transfer Agent (MTA) IP chains via `Received:` headers
- **Application/Transport Layer Security:** Plain HTTP (cleartext port 80) vs HTTPS (TLS port 443) and raw IPv4 link detection

---

## 🚀 How to Run the Project

### 1. Open Terminal / PowerShell
Navigate to the project directory:
```powershell
cd C:\Users\Pandugolla\.gemini\antigravity\scratch\email-threat-detection
```

### 2. Verify / Install Dependencies
Python 3 is required. The necessary libraries are `flask` and `dnspython`:
```powershell
python -m pip install flask dnspython
```

### 3. Run the Automated Test Suite (Optional)
Run the test script to see the rule engine evaluate safe and malicious emails:
```powershell
python test_system.py
```

### 4. Start the Web Server
Launch the Flask development server:
```powershell
python app.py
```

### 5. Open Your Browser
Open your browser and navigate to:
```
http://127.0.0.1:5000/
```

---

## 📁 Project File Structure

```
email-threat-detection/
│
├── app.py                 # Flask server: Handles HTTP GET/POST routes and page rendering
├── detector.py            # Core threat engine: Combines rule evaluation with AI/ML ensemble
├── ml_detector.py         # AI/ML Model: TF-IDF vectorizer + Logistic Regression classifier
├── email_parser.py        # Parses RFC 5322 .eml files, extracts headers, hops, and URLs
├── dns_checker.py         # Performs DNS lookups for MX records, SPF, and DMARC TXT records
├── test_system.py         # Automated CLI testing script
├── VIVA_GUIDE.md          # Complete viva preparation guide and examiner FAQs
├── README.md              # Project setup and usage instructions
│
├── sample_emails/         # Pre-crafted sample emails for live demonstration
│   ├── sample_legitimate.eml             # Clean email with valid SPF/DKIM/DMARC (Score: 0)
│   ├── sample_phishing_urgent_bank.eml   # High-risk bank phishing with raw IP link (Score: 100)
│   └── sample_spoofed_sender.eml         # Spoofed Return-Path vs From header (Score: 100)
│
├── templates/             # Jinja2 HTML templates
│   ├── index.html         # Main dashboard with tabs and 1-click viva test buttons
│   └── result.html        # Comprehensive threat analysis report with CN concept callouts
│
└── static/                # Front-end styling
    └── style.css          # Modern, responsive CSS styling
```

---

## 🎯 How to Demonstrate to Your Teacher

1. **Start the server:** Run `python app.py` and open `http://127.0.0.1:5000/`.
2. **Demonstrate 1-Click Samples:**
   - Click **"🔴 High-Risk Bank Phishing"** &rarr; Form autofills &rarr; Click **Analyze Email**.
   - Show the teacher how the score jumps to High Risk (100/100) due to:
     - Envelope Return-Path mismatch
     - Raw IPv4 address in link (`http://192.168.1.105:8080`)
     - Insecure HTTP instead of HTTPS
     - Social engineering urgency keywords
3. **Demonstrate Clean Email:**
   - Click **"🟢 Clean GitHub Notice"** &rarr; Click **Analyze Email**.
   - Show that score is **0/100 (Low Risk)** and passes all checks.
4. **Demonstrate `.eml` File Upload:**
   - Switch to the **"📁 Upload Saved .eml File"** tab.
   - Upload `sample_phishing_urgent_bank.eml` or `sample_spoofed_sender.eml`.
   - Point out the **Multi-Hop SMTP Relay Routing** section showing how the email hopped across servers with IP addresses extracted!
