# SOC-Alert-Processor
This is a tool for InfoSec professionals looking to automate report generation, freeing up more time for investigation and triage. 

## Prerequisites: 

- Python 3.8+
  
- Google Cloud Project

- Gmail/Outlook access.

## Setup:

- Clone the repo.

- Run pip install -r requirements.txt.

- Place client_secret.json in the root (downloaded from Google Cloud).

- Create a .env file with TEMPLATE_DOC_ID and DRIVE_FOLDER_ID.

## Customization Notes:

- For the 🔧 FIELD EXTRACTION section, if your E/XDR email is not Deep Instinct, you must rewrite the "extract_alert_fields" function there.

- Go to the KNOWN_LABELS list to match the alert field names to your respective E/XDR.

## Usage:

- Drop .eml files into Incoming_emails/.

- Run python soc_alert_automation.py.
