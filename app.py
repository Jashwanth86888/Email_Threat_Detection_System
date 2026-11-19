"""
app.py - Flask Client-Server Web Application
=============================================
Computer Networks Concepts Demonstrated:
1. Client-Server Architecture: Web browser (client) sends HTTP requests to Flask (server).
2. HTTP Methods & Protocol:
   - GET / : Retrieves the web interface.
   - POST /analyze : Submits multipart/form-data with email payloads.
3. MIME Multi-part Parsing: Processing uploaded RFC 5322 .eml files.
4. REST-style Endpoint: Serving sample data as JSON for instant autofill.

Author: Team 21 (Vasavi College of Engineering, CN 5th Sem)
Project: Email Threat Detection Platform (Rule-Based, Non-AI)
"""

import os
from flask import Flask, render_template, request, jsonify, send_from_directory
from email_parser import parse_eml_file_bytes, extract_urls_from_text, analyze_url
from detector import evaluate_email

app = Flask(__name__)
# Maximum upload file size: 10 Megabytes
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.join(BASE_DIR, "sample_emails")


# Predefined sample data for the 1-click test buttons in manual mode
PRESET_SAMPLES = {
    "phishing": {
        "display_name": "State Bank of India Online",
        "sender_email": "security-alert@sbi-fraud-verification-portal.xyz",
        "return_path": "bounce@compromised-server-32.org",
        "subject": "URGENT: Account Suspended - Immediate Action Required within 24 hours!",
        "links": "http://192.168.1.105:8080/sbi/verify_login.php",
        "body_text": "DEAR CUSTOMER,\n\nYOUR SBI BANK ACCOUNT HAS BEEN SUSPENDED DUE TO UNAUTHORIZED ACCESS. IMMEDIATE ACTION REQUIRED WITHIN 24 HOURS OR YOUR NETBANKING ACCESS WILL BE PERMANENTLY BLOCKED.\n\nCLICK HERE IMMEDIATELY TO VERIFY YOUR ACCOUNT:\nhttp://192.168.1.105:8080/sbi/verify_login.php\n\nPLEASE HAVE YOUR DEBIT CARD NUMBER AND OTP READY FOR VERIFICATION."
    },
    "spoofed": {
        "display_name": "PayPal Customer Support",
        "sender_email": "service@paypal.com",
        "return_path": "attacker@free-mailer-relay.net",
        "subject": "Security Alert: Confirm your identity and password expired",
        "links": "http://paypal-resolution-center.biz/update_profile.html",
        "body_text": "Hello,\n\nWe detected unusual activity and your password expired today. Immediate action required: Confirm your identity to prevent access restricted status.\n\nPlease visit the link below to unlock your PayPal account:\nhttp://paypal-resolution-center.biz/update_profile.html\n\nThank you for your prompt attention."
    },
    "safe": {
        "display_name": "GitHub Notifications",
        "sender_email": "notifications@github.com",
        "return_path": "notifications@github.com",
        "subject": "[GitHub] Security advisory alert closed",
        "links": "https://github.com/security/advisories",
        "body_text": "Hi Developer,\n\nThe automated security advisory alert on your repository has been successfully closed. All dependencies are now verified and running the latest stable protocols.\n\nYou can review your repository settings at any time:\nhttps://github.com/security/advisories\n\nThanks,\nThe GitHub Security Team"
    }
}


@app.route('/')
def index():
    """
    Renders the main dashboard interface.
    Computer Networks note: Browser sends an HTTP GET request; server responds with 200 OK + HTML.
    """
    return render_template('index.html')


@app.route('/api/sample/<sample_type>')
def get_sample(sample_type):
    """
    Returns preset sample email data as JSON for instant testing.
    """
    sample = PRESET_SAMPLES.get(sample_type)
    if sample:
        return jsonify(sample)
    return jsonify({"error": "Sample not found"}), 404


@app.route('/download-sample/<filename>')
def download_sample_file(filename):
    """
    Allows the user or teacher to download pre-crafted .eml test files.
    """
    return send_from_directory(SAMPLE_DIR, filename, as_attachment=True)


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Handles form submission and .eml file uploads.
    Performs Computer Networks rule-based threat evaluation.
    """
    # 1. Check if user uploaded a .eml file
    uploaded_file = request.files.get('eml_file')
    
    if uploaded_file and uploaded_file.filename != '':
        file_bytes = uploaded_file.read()
        parsed_data = parse_eml_file_bytes(file_bytes)
        parsed_data["source_type"] = f"Uploaded RFC 5322 EML File ({uploaded_file.filename})"
    else:
        # 2. Manual form input mode
        sender_email = request.form.get('sender_email', '').strip()
        display_name = request.form.get('display_name', '').strip()
        return_path = request.form.get('return_path', '').strip()
        subject = request.form.get('subject', '').strip()
        body_text = request.form.get('body_text', '').strip()
        links_raw = request.form.get('links', '').strip()

        # Combine body links with manually entered links
        urls = extract_urls_from_text(body_text)
        if links_raw:
            for l in links_raw.split():
                if l.strip():
                    urls.append(analyze_url(l.strip()))

        # Deduplicate URLs by host + scheme
        seen_urls = set()
        unique_urls = []
        for u in urls:
            key = u.get("original_url")
            if key not in seen_urls:
                seen_urls.add(key)
                unique_urls.append(u)

        parsed_data = {
            "is_eml": False,
            "source_type": "Manual Input Inspection",
            "sender_email": sender_email,
            "display_name": display_name,
            "return_path": return_path,
            "subject": subject,
            "date": "N/A (Manual Entry)",
            "message_id": "N/A",
            "body_text": body_text,
            "urls": unique_urls,
            "hops": [],
            "auth_results": "",
            "received_spf": "",
            "has_dkim": False
        }

    # Run the rule-based evaluation engine
    result = evaluate_email(parsed_data)

    return render_template(
        'result.html',
        data=parsed_data,
        result=result
    )


if __name__ == '__main__':
    print("===================================================================")
    print(" Email Threat Detection Platform (Rule-Based, Non-AI) ")
    print(" Vasavi College of Engineering - Computer Networks (5th Semester)  ")
    print(" Team No: 21 | Batch: 2                                             ")
    print(" Server running at: http://127.0.0.1:5000/                         ")
    print("===================================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)
