import os
from functools import wraps
from flask import request, jsonify

# firebase_admin is required; make failure explicit with a helpful message
try:
    import firebase_admin
    from firebase_admin import credentials, auth, firestore
except ImportError as ie:
    raise ImportError(
        "The firebase_admin package is not installed. "
        "Run `pip install firebase-admin` in your virtual environment." 
    )

# initialize Firebase Admin SDK once
_sa_path = os.environ.get(
    "FIREBASE_SERVICE_ACCOUNT",
    os.path.join(os.path.dirname(__file__), "serviceAccountKey.json"),
)
if not firebase_admin._apps:
    cred = credentials.Certificate(_sa_path)
    firebase_admin.initialize_app(cred)

# Firestore client to be shared
firestore_client = firestore.client()


def verify_token(id_token: str) -> dict | None:
    """Verify a Firebase ID token and return decoded payload, or None."""
    try:
        return auth.verify_id_token(id_token)
    except Exception as exc:
        # token invalid/expired
        return None


def require_auth(f):
    """Decorator for Flask routes that require a valid Firebase ID token."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "Authorization header missing or invalid"}), 401

        token = header.split(" ", 1)[1]
        decoded = verify_token(token)
        if not decoded:
            return jsonify({"error": "Invalid or expired token"}), 401

        # attach user info for handlers
        request.user = decoded
        return f(*args, **kwargs)

    return wrapper
