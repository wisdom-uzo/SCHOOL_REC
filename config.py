import os

FIREBASE_CONFIG = {
    "apiKey": os.environ.get("FIREBASE_API_KEY", "AIzaSyAVgUqf5DyN3rCxAGKn9S1ZXJh58W9JpnM"),
    "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN", "school-record-system-f01b8.firebaseapp.com"),
    "projectId": os.environ.get("FIREBASE_PROJECT_ID", "school-record-system-f01b8"),
    "storageBucket": os.environ.get("FIREBASE_STORAGE_BUCKET", "school-record-system-f01b8.firebasestorage.app"),
    "messagingSenderId": os.environ.get("FIREBASE_MESSAGING_SENDER_ID", "495853335865"),
    "appId": os.environ.get("FIREBASE_APP_ID", "1:495853335865:web:cbdea960232515bdf6e4e8"),
}

SECRET_KEY = os.environ.get("SECRET_KEY", "school-record-system-secret-key-2026-f01b8")

