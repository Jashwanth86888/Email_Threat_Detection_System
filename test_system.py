"""
test_system.py - Command-Line Verification & Testing Script
===========================================================
Run this script to verify that all modules (email parsing, DNS checking,
and rule-based threat detection) are functioning properly.

Usage:
    python test_system.py
"""

import os
from email_parser import parse_eml_file_bytes
from detector import evaluate_email


def run_tests():
    print("=" * 65)
    print(" Email Threat Detection Platform - Automated Test Suite")
    print(" Team 21 | Vasavi College of Engineering | CN 5th Sem")
    print("=" * 65)

    # 1. Test HackerRank transactional email
    print("\n[+] Testing Legitimate Transactional Email: HackerRank")
    print("-" * 50)
    sample_hackerrank = {
        "sender_email": "support@hackerrank.com",
        "display_name": "HackerRank Support",
        "return_path": "bounces+1234@em.hackerrank.com",
        "subject": "Verify your email address to start coding",
        "body_text": "Hi Candidate,\n\nPlease verify your account by clicking: https://www.hackerrank.com/verify?token=abc\n\nFollow us on LinkedIn: https://www.linkedin.com/company/hackerrank\nTwitter: https://twitter.com/hackerrank",
        "urls": [],
        "is_eml": False
    }
    hr_res = evaluate_email(sample_hackerrank)
    print(f"  From:             {sample_hackerrank['sender_email']}")
    print(f"  Return-Path:      {sample_hackerrank['return_path']}")
    print(f"  Subject:          {sample_hackerrank['subject']}")
    print(f"  --> Rule-Based:   {hr_res.get('rule_score')}/100")
    print(f"  --> AI/ML Model:  {hr_res.get('ml_score')}/100 (P(phish)={hr_res.get('ml_details', {}).get('phishing_probability')})")
    print(f"  --> Final Score:  {hr_res['score']}/100 (Ensemble Average)")
    print(f"  --> Risk Level:   {hr_res['risk_level']}")
    print(f"  --> Triggered:    {hr_res['triggered_count']} rules")
    for rule in hr_res["triggered_rules"]:
        print(f"      * {rule['rule']} ({rule['points']} pts): {rule['details']}")
    
    # 2. Test Sample .EML Files
    sample_dir = os.path.join(os.path.dirname(__file__), "sample_emails")
    if not os.path.exists(sample_dir):
        print(f"Error: Directory '{sample_dir}' not found.")
        return

    files = sorted([f for f in os.listdir(sample_dir) if f.endswith(".eml")])
    
    for filename in files:
        filepath = os.path.join(sample_dir, filename)
        print(f"\n[+] Testing Email File: {filename}")
        print("-" * 50)
        
        with open(filepath, "rb") as f:
            parsed = parse_eml_file_bytes(f.read())
            
        print(f"  From:        {parsed.get('sender_email')}")
        print(f"  Return-Path: {parsed.get('return_path')}")
        print(f"  Subject:     {parsed.get('subject')}")
        print(f"  Hops found:  {len(parsed.get('hops', []))}")
        print(f"  URLs found:  {len(parsed.get('urls', []))}")
        
        result = evaluate_email(parsed)
        
        print(f"  --> Rule-Based:   {result.get('rule_score')}/100")
        print(f"  --> AI/ML Model:  {result.get('ml_score')}/100 (P(phish)={result.get('ml_details', {}).get('phishing_probability')})")
        print(f"  --> Final Score:  {result['score']}/100 (Ensemble Average)")
        print(f"  --> Risk Level:   {result['risk_level']}")
        print(f"  --> Triggered:    {result['triggered_count']} rules")
        
        for rule in result["triggered_rules"]:
            pts_str = f"+{rule['points']}" if rule['points'] > 0 else f"{rule['points']}"
            print(f"      * {rule['rule']} ({pts_str} pts): {rule['details']}")

    print("\n" + "=" * 65)
    print(" [OK] All sample tests completed successfully!")
    print("=" * 65)


if __name__ == "__main__":
    run_tests()
