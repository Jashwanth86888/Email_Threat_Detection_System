# Viva Voce & Examiner Guide
## Hybrid Email Threat Detection Platform (Rule-Based + AI/ML Ensemble)
**Course:** Computer Networks (5th Semester B.Tech)  
**Institution:** Vasavi College of Engineering  
**Team No:** 21 | **Batch:** 2  
**Team Members:** 1602-24-737-164, 1602-24-737-163, 1602-24-737-165  

---

## 1. Project Summary in 30 Seconds (Elevator Pitch)
> *"Our project is a **Hybrid Email Threat Detection Platform** built with Python and Flask. It uses an **Ensemble Architecture** combining two independent detection layers: (1) a deterministic **Rule-Based Engine** that verifies Computer Networks RFC protocols (SMTP envelope alignment, DNS MX records, SPF/DKIM verification, and HTTP vs HTTPS), and (2) an **AI/ML Machine Learning Classifier** utilizing TF-IDF text n-grams and regularized Logistic Regression. The system independently computes points for both engines and calculates the **arithmetic average** `(Rule_Score + ML_Score) / 2` to determine the final threat points and risk level."*

---

## 2. Mapping to the OSI & TCP/IP Model

| Layer | Protocol / Concept in Project | Where it appears in the Code |
|---|---|---|
| **Application Layer** | **HTTP / HTTPS:** Client sends requests, server returns HTML/JSON | `app.py` routes, HTTP vs HTTPS check in URLs |
| **Application Layer** | **SMTP (RFC 5321 & 5322):** Header vs Envelope alignment | `email_parser.py` extracting `From` vs `Return-Path` |
| **Application Layer** | **DNS (Domain Name System):** Resolving hostnames, querying MX and TXT records | `dns_checker.py` querying A, MX, SPF, DMARC |
| **Transport Layer** | **TCP Ports:** Port 80 (HTTP cleartext), Port 443 (HTTPS TLS), Port 25/587 (SMTP) | `email_parser.py` checking URL port and scheme |
| **Network Layer** | **IPv4 / Addressing:** Raw IP addresses in hyperlinks and `Received` headers | `email_parser.py` regex `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` |
| **Cross-Layer AI/ML** | **Ensemble Learning & NLP:** TF-IDF n-grams + Logistic Regression | `ml_detector.py` calculating P(Phishing) and feature weights |

---

## 3. End-to-End Execution Flow (How the Code Works)

```
[Web Browser (Client)]
        │
        │ HTTP POST /analyze (Form data or .eml file)
        ▼
   [app.py (Flask Server)]
        │
        ├── 1. email_parser.py: Extracts From, Return-Path, Subject, Received hops, URLs
        │
        ├── 2. dns_checker.py: Queries DNS for sender domain (A records, MX, SPF, DMARC)
        │
        ├── 3. detector.py: Evaluates 6 CN rules -> Computes Rule_Score (0 - 100)
        │
        ├── 4. ml_detector.py: Extracts TF-IDF + structural features -> Computes ML_Score (0 - 100)
        │
        ├── 5. Hybrid Ensemble: Final_Score = round((Rule_Score + ML_Score) / 2)
        │                       Determines Threat Level: Low (<30), Suspicious (30-59), High (>=60)
        ▼
   [Renders result.html]
        │
        │ HTTP 200 OK + Visual Tri-Metric Report
        ▼
[Web Browser renders Rule Score, ML Score, Final Average, and CN & ML explanations]
```

---

## 4. In-Depth Explanation of the 6 Rules

### Rule 1: Sender Spoofing & Return-Path Mismatch (+25 pts)
- **Computer Networks Concept:** SMTP Message Architecture (RFC 5321 vs RFC 5322).
- **Explanation:** When SMTP was invented in 1982 (RFC 821), there was no authentication. An email has two senders:
  1. The **Envelope Sender** (`MAIL FROM` / `Return-Path`): Used by mail servers for routing and bounce messages (RFC 5321).
  2. The **Header Sender** (`From:`): Displayed to the end user by their email client (RFC 5322).
- **Why it flags:** In a spoofing attack, an attacker sets the `From:` header to `support@paypal.com` but the envelope sender is `attacker@bad-server.net`. Our code flags this discrepancy.

### Rule 2: DNS & MX Record Verification (+20 to +35 pts)
- **Computer Networks Concept:** Domain Name System (DNS) Resource Records.
- **Explanation:**
  - An **A record** maps a domain to an IPv4 address. If `socket.getaddrinfo()` returns NXDOMAIN (Non-Existent Domain), the sender domain does not exist!
  - An **MX record (Mail Exchange)** tells the Internet which servers are authorized to receive emails for that domain.
- **Why it flags:** A legitimate organization sending email must have valid MX records configured so that delivery status notifications (NDRs) and replies can reach them. If a domain has no MX records, it is a throwaway or misconfigured domain.

### Rule 3: Email Authentication Status (SPF, DKIM, DMARC) (+10 to +30 pts)
- **Computer Networks Concept:** Cryptographic and DNS-based Email Security Standards.
- **Explanation:**
  - **SPF (Sender Policy Framework - RFC 7208):** The domain owner publishes a TXT record in DNS (e.g., `v=spf1 ip4:140.82.114.25 -all`). When an email arrives, the receiver inspects the connecting client's IP address. If the IP is not in the SPF record, the SPF check fails.
  - **DKIM (DomainKeys Identified Mail - RFC 6376):** Uses asymmetric cryptography (RSA). The sender signs headers using their private key (`DKIM-Signature:`). The receiver fetches the sender's public key from DNS to verify that the message was not tampered with in transit.
  - **DMARC (RFC 7489):** Aligns the visible `From:` domain with SPF and DKIM, and instructs the receiver what policy to apply (`none`, `quarantine`, or `reject`) if validation fails.

### Rule 4: Suspicious URLs & Raw IPv4 Addresses (+10 to +30 pts)
- **Computer Networks Concept:** URI Syntax (RFC 3986), Transport Layer Security (HTTP vs HTTPS), and IP Addressing.
- **Explanation:**
  - **Raw IP Address:** Legitimate businesses always use registered domain names (e.g., `https://onlinesbi.sbi/`) with valid SSL/TLS certificates. Phishers often host temporary credential harvesting scripts on raw IP addresses (e.g., `http://192.168.1.105:8080/login.php`) to avoid domain registration records and blacklists.
  - **Plain HTTP:** HTTP communicates over TCP port 80 in cleartext. Sensitive login forms must use HTTPS over TCP port 443 with TLS encryption.

### Rule 5: Social Engineering & Urgency Keywords (+10 to +25 pts)
- **Computer Networks Concept:** Application-Layer Payload Inspection.
- **Explanation:** Firewalls and Network Intrusion Detection Systems (NIDS) inspect payload patterns. Attackers use psychological triggers ("account suspended", "immediate action required", "password expired") to induce panic so the victim clicks without verifying the transport-layer sender.

### Rule 6: Multi-Hop SMTP Routing & Relay Analysis (+10 pts)
- **Computer Networks Concept:** Store-and-Forward Email Relaying.
- **Explanation:** Every intermediate SMTP Mail Transfer Agent (MTA) prepends a `Received:` header line recording the sender host, IP address, recipient, and timestamp.
- **Why it flags:** Reading `Received:` headers from bottom to top reconstructs the packet's travel path. If an email traversed an unusually high number of hops (>6), it suggests proxy chaining, bulletproof relays, or open-relay abuse.

---

## 5. Top 10 Viva Questions & Model Answers

### Q1: "Why did you build an Ensemble combining Rule-Based and AI/ML models?"
**Answer:**  
*"Because neither approach alone is sufficient for robust cybersecurity! A purely rule-based system can miss novel social engineering wording and contextual tricks, while a pure machine learning model can be bypassed by subtle word changes and acts as an unexplainable black box. By creating an Ensemble that combines deterministic network protocol checks (SMTP, DNS, SPF/DKIM, TLS) with probabilistic natural language classification (TF-IDF + Logistic Regression), our system catches both protocol-level forgery and content-level social engineering, averaging both scores to minimize false positives and false negatives."*

### Q2: "What is the difference between RFC 5321 and RFC 5322 in email?"
**Answer:**  
*"RFC 5321 defines the SMTP protocol for message transmission between mail servers—it defines the envelope sender (`MAIL FROM`), which determines where bounce errors are routed (`Return-Path`). RFC 5322 defines the format and syntax of the message body and headers displayed to the end-user (such as `From:`, `To:`, and `Subject:`). Email spoofing occurs because standard SMTP does not enforce that the RFC 5322 `From` header must match the RFC 5321 `MAIL FROM` envelope."*

### Q3: "What is an MX record, and why does your system check it?"
**Answer:**  
*"An MX (Mail Exchange) record is a DNS resource record that specifies the mail server responsible for accepting incoming email on behalf of a domain, along with a preference value. Our system queries the sender domain's DNS for MX records. If a domain sends an email but has no MX records, it is suspicious because legitimate email domains must have an MX server to receive delivery status notifications (NDRs) or user replies."*

### Q4: "How does SPF (Sender Policy Framework) work?"
**Answer:**  
*"SPF works through DNS TXT records. The domain owner publishes a record like `v=spf1 ip4:192.0.2.1 -all`. When the receiving mail server gets a TCP connection from a sending MTA, it extracts the client's IP address and queries the DNS TXT record of the sender's domain. If the client IP is listed, SPF passes; if not, it returns a softfail or fail."*

### Q5: "What is DKIM and how does it prevent tampering?"
**Answer:**  
*"DKIM (DomainKeys Identified Mail) provides cryptographic integrity and sender authentication using asymmetric public-key cryptography. The sending server hashes the email headers and body, encrypts the hash using its private key, and attaches it as a `DKIM-Signature` header. The receiving server fetches the sender's public key from a DNS TXT record (`selector._domainkey.domain.com`) and decrypts the signature. If the decrypted hash matches the calculated hash, the email has not been modified in transit."*

### Q6: "Why is a raw IP address in a link considered a threat?"
**Answer:**  
*"Under RFC 3986, URLs can use either hostnames or IP addresses. However, legitimate financial or corporate institutions register domain names and obtain TLS/SSL certificates bound to those domains. Attackers use raw IP addresses (e.g., `http://192.168.1.105:8080/login`) to host phishing pages on compromised servers without registering domains, or to evade domain-based reputation blacklists."*

### Q7: "How did your project extract relay hops from an email?"
**Answer:**  
*"Whenever an SMTP server forwards an email, it prepends a `Received:` header to the top of the message containing the sending server's name, IP address, and timestamp. In Python, our `email_parser.py` extracts all `Received` headers using `msg.get_all('Received')` and uses regular expressions to extract IP addresses inside brackets `[x.x.x.x]`. This allows us to trace the email's physical relay path across the Internet."*

### Q8: "What is the difference between HTTP and HTTPS in your URL check?"
**Answer:**  
*"HTTP operates over unencrypted TCP port 80. All data, including usernames, passwords, and form submissions, travels in plaintext, making it vulnerable to packet sniffing and Man-in-the-Middle (MITM) attacks. HTTPS operates over TCP port 443 with TLS encryption, guaranteeing confidentiality and server authentication. Finding cleartext HTTP links in modern banking or security emails is an immediate red flag."*

### Q9: "How does your client-server architecture work in Flask?"
**Answer:**  
*"The web browser acts as the HTTP client, and our Python application running Flask acts as the HTTP server. When the user enters email data or uploads an `.eml` file, the browser sends an HTTP `POST` request with `multipart/form-data`. Flask receives the request, routes it to the `/analyze` function, triggers `email_parser.py`, `dns_checker.py`, and `detector.py`, calculates the threat score, and renders the dynamic `result.html` template back to the client with an HTTP `200 OK` status."*

### Q10: "What is DMARC and why is it needed if we already have SPF and DKIM?"
**Answer:**  
*"SPF only verifies the envelope sender (`MAIL FROM`), and DKIM only verifies that the signature belongs to some domain, but neither guarantees that the visible `From:` header shown to the user is authentic! DMARC (Domain-based Message Authentication, Reporting, and Conformance) requires 'Identifier Alignment', meaning the domain in the visible `From:` header must match the SPF or DKIM domain. It also publishes a policy instructing receivers whether to reject or quarantine failing emails."*

### Q11: "How does the AI/ML model calculate points in its own way?"
**Answer:**  
*"The AI/ML module (`ml_detector.py`) uses a scikit-learn pipeline featuring a TF-IDF N-Gram Vectorizer (1-gram and 2-grams) and an engineered structural feature extractor (URL count, raw IP presence, cleartext HTTP, domain mismatch, uppercase urgency ratio). It feeds this combined feature matrix into a regularized Logistic Regression classifier that computes the posterior probability of an email being phishing: $P(\text{Phishing}) \in [0, 1]$. We scale this probability directly into integer points from 0 to 100: $\text{ML Score} = \text{round}(P(\text{Phishing}) \times 100)$."*

### Q12: "How is the final threat score and risk level calculated from both engines?"
**Answer:**  
*"The platform calculates the arithmetic average of the two independent scores:
$$\text{Final Ensemble Score} = \text{round}\left(\frac{\text{Rule-Based Score} + \text{AI/ML Score}}{2}\right)$$
The final threat level is categorized based on these final points:
- **0 to 29 Points:** Low Risk / Legitimate (Green)
- **30 to 59 Points:** Suspicious / Moderate Risk (Amber)
- **60 to 100 Points:** High Risk / Phishing (Red)"*

### Q13: "What is Explainable AI (XAI) and how is it used in your ML module?"
**Answer:**  
*"Because pure neural networks and complex models often obscure how decisions are made, we implemented Explainable AI (XAI) using Logistic Regression linear coefficients ($w_i$). For any analyzed email, the system calculates feature impact ($\text{impact}_i = w_i \times x_i$) and extracts the top positive contributors (e.g., 'Raw IP in URL', 'Cleartext HTTP', 'Urgency Keyword: suspended'). These top predictive indicators are displayed directly on the results dashboard."*
