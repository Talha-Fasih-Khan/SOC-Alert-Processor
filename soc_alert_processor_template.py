#!/usr/bin/env python3
"""
SOC Alert Automation Script
-----------------------------------------------------------
Purpose: Automatically parses E/XDR alert emails (.eml files),
extracts threat details, and creates formatted Google Docs.

Requirements:
- Python 3.8+
- Google Cloud Project with Drive & Docs APIs enabled
- OAuth 2.0 Client Secret (client_secret.json)
- .env file with TEMPLATE_DOC_ID and DRIVE_FOLDER_ID
-----------------------------------------------------------
"""

# ---------------------- STANDARD LIBRARIES ----------------------
import os
import json
import datetime
import re
import pickle
import sqlite3
from dotenv import load_dotenv

# ---------------------- GOOGLE LIBRARIES ----------------------
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# ---------------------- EMAIL & HTML PARSING ----------------------
import email
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup

# ================================================================
# 🔧 1. CONFIGURATION & AUTHENTICATION
# ================================================================

# Google OAuth Scopes
# NOTE: 'drive' scope is required to copy templates created manually.
# If you only create files via the script, you could restrict to 'drive.file'.
SCOPES = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/documents'
]

# Load environment variables
load_dotenv()
TEMPLATE_DOC_ID = os.getenv("TEMPLATE_DOC_ID")
DRIVE_FOLDER_ID = os.getenv("DRIVE_FOLDER_ID")  # Optional

def get_google_service(service_name, version):
    """
    Authenticates using OAuth 2.0 with local token storage.
    If token.pickle is missing or expired, it opens a browser for login.
    """
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('client_secret.json', SCOPES)
            creds = flow.run_local_server(port=0)
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)

    service = build(service_name, version, credentials=creds)
    return service


# ================================================================
# 🔧 2. EMAIL PARSING (Works for any .eml)
# ================================================================

def parse_eml_file(file_path):
    """
    Reads a .eml file, decodes the body, and returns subject, sender, and HTML body.
    This part is generic and works for any email.
    """
    with open(file_path, 'rb') as file:
        msg = BytesParser(policy=policy.default).parse(file)
    
    payload_bytes = msg.get_payload(decode=True)
    body = payload_bytes.decode('utf-8', errors='ignore')
    
    subject = msg['Subject']
    sender = msg['From']
    
    return {"subject": subject, "sender": sender, "body": body}


# ================================================================
# 🔧 3. FIELD EXTRACTION (⚠️ CUSTOMIZATION REQUIRED)
# ================================================================
# WARNING: This section is hardcoded for Deep Instinct HTML structure.
# If you use a different E/XDR (SentinelOne, CrowdStrike, etc.),
# you MUST update this logic.

KNOWN_LABELS = [
    "Event ID", "Occurrences", "Start Date", "Received on Server",
    "Last Occurrence", "Event Type", "Deep Classification",
    "Threat Severity", "Details", "File Type", "File Hash",
    "MITRE ATT&CK", "Device IP", "Device Name", "Platform",
    "Logged in Users"
]

def extract_alert_fields(html_body):
    """
    Extracts key-value pairs from the email HTML.
    CURRENT LOGIC: Assumes data is in a table with rows containing 5 cells,
    where the first cell has the label and value concatenated (e.g., "Event ID12345").
    """
    soup = BeautifulSoup(html_body, 'html.parser')
    
    # Step 1: Find the table with the most 2-cell rows (identifies the main data table)
    best_table = None
    best_count = 0
    for table in soup.find_all('table'):
        count = 0
        for row in table.find_all('tr'):
            if len(row.find_all('td')) == 2:
                count += 1
        if count > best_count:
            best_count = count
            best_table = table
    
    if best_table is None:
        print("Warning: No table with 2-cell rows found")
        return {}
    
    fields = {}
    
    # Step 2: Look for rows with 4+ cells (Deep Instinct specific) 
    # to extract the concatenated label+value text.
    for row in best_table.find_all('tr'):
        cells = row.find_all('td')
        if len(cells) >= 4:
            text = cells[0].get_text(strip=True)
            for label in KNOWN_LABELS:
                if text.startswith(label):
                    value = text[len(label):]
                    fields[label] = value
                    break
    
    return fields


# ================================================================
# 🔧 4. MITRE PARSING (⚠️ CUSTOMIZATION REQUIRED)
# ================================================================
# This regex is specifically for Deep Instinct's "mitreId=TA0040.T1486..." format.
# Other E/XDRs might just send a comma-separated list or simple T-code.

def parse_mitre(mitre_string):
    """
    Parses Deep Instinct MITRE format into Tactic, Technique, and Sub-Technique.
    Please feel free to modify according to your E/XDR tool of choice
    """
    result = {}
    
    tactic_match = re.search(r'mitreTactic=(\S+)', mitre_string)
    if tactic_match:
        result['MITRE Tactic'] = tactic_match.group(1)
    
    id_match = re.search(r'mitreId=([\S.]+)', mitre_string)
    if id_match:
        full_id = id_match.group(1)
        if '.' in full_id:
            result['MITRE Technique'] = full_id.split('.')[1]
        else:
            result['MITRE Technique'] = full_id
    
    sub_match = re.search(r'mitreSubTechnique=(.+)', mitre_string)
    if sub_match:
        result['MITRE Sub-Technique'] = sub_match.group(1)
    
    return result


# ================================================================
# 🔧 5. GOOGLE DOC GENERATION (Generic)
# ================================================================

def copy_and_fill_template(fields):
    """
    Copies the template Google Doc and replaces {{PLACEHOLDERS}} with data.
    """
    drive_service = get_google_service('drive', 'v3')
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    new_name = f"Alert Report - {fields.get('Event ID', 'Unknown')} - {timestamp}"
    
    file_body = {'name': new_name}
    if DRIVE_FOLDER_ID:
        file_body['parents'] = [DRIVE_FOLDER_ID]
    
    copied_file = drive_service.files().copy(
        fileId=TEMPLATE_DOC_ID,
        body=file_body
    ).execute()
    
    new_doc_id = copied_file.get('id')
    print(f"✅ New document created: {new_name}")
    print(f"🔗 Link: https://docs.google.com/document/d/{new_doc_id}/edit")
    
    # Fill placeholders
    docs_service = get_google_service('docs', 'v1')
    requests = []
    for label, value in fields.items():
        requests.append({
            'replaceAllText': {
                'containsText': {'text': f'{{{{{label}}}}}', 'matchCase': True},
                'replaceText': value
            }
        })
    
    if requests:
        docs_service.documents().batchUpdate(
            documentId=new_doc_id,
            body={'requests': requests}
        ).execute()
        print("✅ Placeholders replaced with alert data")
    else:
        print("⚠️ No fields to replace")
    
    return new_doc_id


# ================================================================
# 🔧 6. DATABASE HELPERS (Prevents Duplicates)
# ================================================================

def init_db():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS processed_alerts (
            event_id INTEGER PRIMARY KEY,
            device_name TEXT,
            threat_severity TEXT,
            ip_reputation_score INTEGER,
            report_link TEXT,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_alert(alert_data):
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO processed_alerts 
        (event_id, device_name, threat_severity, ip_reputation_score, report_link)
        VALUES (?, ?, ?, ?, ?)
    """, (
        int(alert_data['event_id']),
        str(alert_data['device_name']),
        str(alert_data['threat_severity']),
        alert_data['ip_reputation_score'],
        str(alert_data['report_link'])
    ))
    conn.commit()
    conn.close()

def alert_exists(event_id):
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM processed_alerts WHERE event_id = ?", (event_id,))
    result = cursor.fetchone()
    conn.close()
    return result is not None


# ================================================================
# 🔧 7. CORE PROCESSING LOGIC
# ================================================================

def process_single_email(file_path):
    try:
        email_data = parse_eml_file(file_path)
        extracted = extract_alert_fields(email_data["body"])
        
        event_id = extracted.get("Event ID")
        if not event_id:
            print(f"⚠️ No Event ID found. Skipping.")
            return "FAILURE"
        
        if alert_exists(event_id):
            print(f"⏭️ Duplicate alert {event_id} found. Skipping.")
            return "DUPLICATE"
        
        # Parse MITRE if it exists
        if "MITRE ATT&CK" in extracted:
            mitre_parts = parse_mitre(extracted["MITRE ATT&CK"])
            extracted.update(mitre_parts)

        # Create the Google Doc
        new_doc_id = copy_and_fill_template(extracted)
        report_link = f"https://docs.google.com/document/d/{new_doc_id}/edit"

        # Save to database
        alert_data = {
            'event_id': int(event_id),
            'device_name': extracted.get('Device Name', 'Unknown'),
            'threat_severity': extracted.get('Threat Severity', 'Unknown'),
            'ip_reputation_score': None,  # Future expansion: Threat Intel API
            'report_link': report_link
        }
        save_alert(alert_data)

        return new_doc_id
    except Exception as e:
        print(f"❌ ERROR processing {file_path}: {e}")
        return "FAILURE"


# ================================================================
# 🔧 8. MAIN EXECUTION (BATCH PROCESSOR)
# ================================================================

if __name__ == "__main__":
    # Initialize database
    init_db()

    # Folder configuration
    INCOMING_FOLDER = "Incoming_emails"
    PROCESSED_FOLDER = "processed_emails"
    
    os.makedirs(INCOMING_FOLDER, exist_ok=True)
    os.makedirs(PROCESSED_FOLDER, exist_ok=True)

    # List all .eml files
    all_files = os.listdir(INCOMING_FOLDER)
    eml_files = [f for f in all_files if f.lower().endswith('.eml')]

    print(f"📂 Found {len(eml_files)} email(s) to process.\n")

    new_count = 0
    dup_count = 0
    fail_count = 0

    for filename in eml_files:
        file_path = os.path.join(INCOMING_FOLDER, filename)
        result = process_single_email(file_path)
        
        dest_path = os.path.join(PROCESSED_FOLDER, filename)

        if result == "DUPLICATE":
            os.rename(file_path, dest_path)
            print(f"📁 Moved {filename} -> processed_emails/ (duplicate)\n")
            dup_count += 1
        elif result and result != "FAILURE":
            os.rename(file_path, dest_path)
            print(f"📁 Moved {filename} -> processed_emails/ (new report)\n")
            new_count += 1
        else:
            print(f"❌ FAILED: {filename} kept in Incoming_emails/ for review.\n")
            fail_count += 1

    print(f"\n=== Summary ===")
    print(f"✅ New reports: {new_count}")
    print(f"⏭️ Duplicates skipped: {dup_count}")
    print(f"❌ Failed: {fail_count}")