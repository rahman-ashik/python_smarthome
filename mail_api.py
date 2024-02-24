import base64
import csv
import json
import email
import os
import logging
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_FILE_PATH = "token.json"
CREDENTIALS_FILE_PATH = "credentials.json"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def authenticate_gmail():
    """Authenticate with Gmail API and return credentials."""
    creds = None
    if os.path.exists(TOKEN_FILE_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE_PATH, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE_PATH, "w") as token:
            token.write(creds.to_json())
    return creds


def fetch_gmail_labels(service):
    """Fetch and print user's Gmail labels."""
    try:
        results = service.users().labels().list(userId="me").execute()
        labels = results.get("labels", [])

        if not labels:
            print("No labels found.")
            return
        print("Labels:")
        for label in labels:
            print(label["name"])

    except HttpError as error:
        logger.error(f"An error occurred while fetching labels: {error}")



def extract_and_save_data(file_path):
    """Extract the 2nd and the last column and save to data.txt."""
    try:
        with open(file_path, 'r', encoding='utf-8') as csv_file:
            csv_reader = csv.reader(csv_file)
            data = list(csv_reader)

            # Check if the file is empty
            is_file_empty = os.path.getsize("data.txt") == 0

            for idx, row in enumerate(data):
                print(row)

                if len(row) >= 2:
                    second_column = row[1]
                    last_column = row[-1]

                    with open("data.txt", "a", encoding="utf-8") as data_file:
                        # Append the data without adding the header
                        if not (is_file_empty and idx == 0):
                            data_file.write(f"{second_column},{last_column}\n")

    except Exception as e:
        print(f"An error occurred while extracting and saving data: {e}")

    finally:
        # Delete the CSV file after extraction
        try:
            os.remove(file_path)
        except FileNotFoundError:
            pass




def fetch_and_process_emails(service, subject):
    try:
        # Search for emails with the specified subject
        response = service.users().messages().list(userId="me", q=f"subject:{subject}").execute()

        if 'messages' not in response:
            print("No emails found with the specified subject.")
            return

        for email_data in response['messages']:
            email_id = email_data['id']
            print(email_id)
            message = service.users().messages().get(userId="me", id=email_id).execute()
            print(message)

            # Check if the email has attachments
            if 'parts' in message['payload']:
                subject = next((header['value'] for header in message['payload']['headers'] if header['name'] == 'Subject'), None)
                print(f"Subject: {subject}")

                sender = next((header['value'] for header in message['payload']['headers'] if header['name'] == 'From'), None)
                print(f"From: {sender}")

                for part in message['payload']['parts']:
                    if 'filename' in part:
                        filename = part['filename']
                        if filename.endswith('.CSV'):
                            # Download the CSV attachment
                            file_data = service.users().messages().attachments().get(
                                userId="me", messageId=email_id, id=part['body']['attachmentId']
                            ).execute()

                            file_content = file_data['data']
                            csv_content = base64.urlsafe_b64decode(file_content.encode('UTF-8'))

                            # Save the CSV content to a local file
                            save_path = os.path.join(os.getcwd(), filename)
                            with open(save_path, 'wb') as csv_file:
                                csv_file.write(csv_content)

                            # Display information about the downloaded CSV
                            print(f"Attachment: {filename}")
                            print(f"CSV content saved to: {save_path}")

                            extract_and_save_data(save_path)

    except HttpError as error:
        logger.error(f"An error occurred while fetching and processing emails: {error}")



def main():
    try:
        # Call the Gmail API
        service = build("gmail", "v1", credentials=authenticate_gmail())
        fetch_gmail_labels(service)

        # Specify the subject to search
        subject_to_search = "Smart Meter Texas – Subscription Report"
        fetch_and_process_emails(service, subject_to_search)

    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
