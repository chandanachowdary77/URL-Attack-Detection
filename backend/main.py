#!/usr/bin/env python3
"""
URL Attack Detection System - API Backend (React Ready)

Dependencies are listed in ../requirements.txt.  Before running the server,
activate your venv and execute:

    pip install -r requirements.txt

If you prefer manual installation, ensure:
  flask
  flask-cors
  firebase-admin
  requests
are present in your environment.
"""

import argparse
import sys
import os
import sqlite3

# make sure the current directory (backend/) is on the import path
# so that `import auth` will work when main.py is executed directly
sys.path.insert(0, os.path.dirname(__file__))
from pathlib import Path
from datetime import datetime
# core framework imports - verify at runtime so missing packages produce a clear message
try:
    from flask import Flask, request, jsonify, session, send_file, Response
    from flask_cors import CORS
except ImportError as ie:
    raise ImportError(
        "Flask and flask-cors must be installed in the virtual environment. "
        "Run `pip install flask flask-cors` and try again."
    )
import requests

# bring in authentication & Firestore client
from auth import require_auth, firestore_client
from firebase_admin import firestore  # to reference Query constants

# optional Firebase Admin for verifying ID tokens
firebase_admin = None
try:
    import firebase_admin
    from firebase_admin import credentials as firebase_credentials, auth as firebase_auth
    # expect service account JSON path via environment variable for flexibility
    sa_path = os.environ.get('FIREBASE_SERVICE_ACCOUNT',
                              os.path.join(Path(__file__).parent, 'serviceAccountKey.json'))
    if os.path.exists(sa_path):
        cred = firebase_credentials.Certificate(sa_path)
        firebase_admin.initialize_app(cred)
    else:
        print("Firebase service account file not found, skipping admin init")
except Exception as e:
    print("Firebase admin SDK not available or failed to initialize:", e)


def verify_token(id_token):
    """Verify Firebase ID token and return decoded payload."""
    if not firebase_admin:
        return None
    try:
        decoded = firebase_auth.verify_id_token(id_token)
        return decoded
    except Exception as e:
        print("Token verification failed", e)
        return None


def require_auth(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
        else:
            return jsonify({'error': 'Authorization header missing or invalid'}), 401
        decoded = verify_token(token)
        if not decoded:
            # if firebase admin not configured, fall back to using token as uid
            if not firebase_admin:
                decoded = {'uid': token}
            else:
                return jsonify({'error': 'Invalid or expired token'}), 401
        # attach user info to request
        request.user = decoded
        return f(*args, **kwargs)
    return wrapper
import csv
from io import StringIO
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))

from dataset_generator import AttackDatasetGenerator
from attack_detector import URLAttackDetector
from database import AttackDatabase
from pcap_analyzer import process_pcap
from ml_model import predict_url
from ai_explainer import explain_attack

app = Flask(__name__)
app.secret_key = "super-secret-key"

CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# authentication state
from werkzeug.security import generate_password_hash, check_password_hash
import random

# simple in-memory user store; add `verified` flag
users = {
    "admin": {"email": "admin@test.com", "password_hash": generate_password_hash("admin123"), "verified": True},
    "user1": {"email": "user1@test.com", "password_hash": generate_password_hash("user123"), "verified": True}
}

# OTPs pending verification (username -> otp string)
pending_otps = {}


db = AttackDatabase()
detector = URLAttackDetector()
generator = AttackDatasetGenerator()

# =====================================
# ANALYZE ROUTE (FINAL VERSION)
# =====================================

@app.route("/api/analyze", methods=["POST"])
@require_auth
def analyze_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL required"}), 400

    # --- first, try to see if Firestore already contains the URL for this user ---
    uid = request.user.get('uid')
    try:
        col = (
            firestore_client
            .collection("users")
            .document(uid)
            .collection("detections")
        )
        fs_query = col.where("url", "==", url).order_by("timestamp", direction=firestore.Query.DESCENDING).limit(1)
        existing_fs = list(fs_query.stream())
        if existing_fs:
            doc = existing_fs[0].to_dict()
            return jsonify({
                "url": url,
                "is_malicious": True,
                "already_analyzed": True,
                "note": "This URL was already analyzed earlier (from Firestore).",
                "severity": doc.get("severity"),
                "confidence": doc.get("confidence"),
                "occurrence_count": doc.get("occurrence_count", 1),
                "last_analyzed": doc.get("timestamp"),
                "ai_explanation": doc.get("ai_explanation", "")
            })
    except Exception:
        pass

    # --- existing SQLite check ---
    conn = sqlite3.connect(db.db_path)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT severity, confidence, occurrence_count, timestamp, ai_explanation
    FROM attacks
    WHERE url = ? AND user_id = ?
    ORDER BY timestamp DESC
    LIMIT 1
    """, (url, uid))

    existing = cursor.fetchone()
    conn.close()

    if existing:
        return jsonify({
            "url": url,
            "is_malicious": True,
            "already_analyzed": True,
            "note": "This URL was already analyzed earlier.",
            "severity": existing[0],
            "confidence": existing[1],
            "occurrence_count": existing[2],
            "last_analyzed": existing[3],
            "ai_explanation": existing[4]
        })

    # Analyze
    result = detector.analyze_url(url)

    # ML fallback
    if not result["is_malicious"]:
        ml_prediction, ml_confidence = predict_url(url)

        if ml_prediction and ml_prediction != "safe" and ml_confidence > 0.75:
            result["is_malicious"] = True
            result["severity"] = "medium"
            result["confidence"] = ml_confidence
            result["attacks_detected"] = [{
                "type": ml_prediction,
                "pattern_matched": "ML Model Detection",
                "confidence": ml_confidence
            }]

    response_code = None
    try:
        response = requests.get(url, timeout=5)
        response_code = str(response.status_code)
    except Exception:
        response_code = None

    is_successful = (
    result["is_malicious"]
    and response_code == "200"
    and result["severity"] in ["high", "critical"]
)

    user_id = request.user.get('uid', '')
    attack_data = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": request.remote_addr,
        "url": url,
        "method": "GET",
        "user_agent": request.headers.get("User-Agent", ""),
        "attack_type": result["attacks_detected"][0]["type"]
        if result["attacks_detected"] else "none",
        "is_malicious": result["is_malicious"],
        "is_successful": is_successful,
        "severity": result["severity"],
        "confidence": result["confidence"],
        "pattern_matched": result["attacks_detected"][0]["pattern_matched"]
        if result["attacks_detected"] else "",
        "source_type": "manual",
        "source_file": "",
        "user_id": user_id
    }

    # ✅ SAVE ONLY IF MALICIOUS
    if result["is_malicious"]:

        db.insert_attack(attack_data)

        try:
            fs_doc = (
                firestore_client
                .collection("users")
                .document(user_id)
                .collection("detections")
                .document()
            )
            fs_doc.set(attack_data)
        except Exception as e:
            app.logger.warning("Failed to write to Firestore: %s", e)

    result["response_code"] = response_code
    result["is_successful"] = is_successful
    result["note"] = "New analysis recorded."
    result["already_analyzed"] = False

    return jsonify(result)

# ========== AUTH API ENDPOINTS ===========

def generate_otp():
    # simple 6-digit random OTP
    return f"{random.randint(100000, 999999)}"


@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"success": False, "message": "username, email and password required"}), 400
    if username in users:
        return jsonify({"success": False, "message": "Username already exists"}), 400

    # create unverified user account and send otp
    otp = generate_otp()
    pending_otps[username] = otp
    users[username] = {"email": email, "password_hash": generate_password_hash(password), "verified": False}
    app.logger.info(f"Generated OTP for {username}: {otp}")

    # NOTE: integration with real email service would go here
    return jsonify({"success": True, "message": "OTP sent to email", "username": username})


@app.route("/api/verify-otp", methods=["POST"])
def api_verify_otp():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    otp = data.get("otp", "").strip()

    if not username or not otp:
        return jsonify({"success": False, "message": "username and otp required"}), 400
    expected = pending_otps.get(username)
    if not expected:
        return jsonify({"success": False, "message": "No OTP pending for this user"}), 400
    if otp != expected:
        return jsonify({"success": False, "message": "Invalid OTP"}), 400

    users[username]["verified"] = True
    pending_otps.pop(username, None)

    # automatically log the user in
    session["username"] = username
    session.permanent = True

    return jsonify({"success": True})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400
    user = users.get(username)
    if not user:
        return jsonify({"success": False, "message": "Invalid username or password"}), 401
    if not user.get("verified"):
        return jsonify({"success": False, "message": "Account not verified. Please check your email for OTP."}), 403
    if not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "message": "Invalid username or password"}), 401

    session["username"] = username
    session.permanent = True
    return jsonify({"success": True})


@app.route("/api/logout", methods=["GET"])
def api_logout():
    session.clear()
    return jsonify({"success": True})

# =====================================
# PCAP ROUTE (UPDATED WITH REQUIRED LOGIC)
# =====================================

@app.route("/api/upload-pcap", methods=["POST"])
@require_auth
def upload_pcap():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    upload_folder = os.path.join(Path(__file__).parent, "uploads")
    os.makedirs(upload_folder, exist_ok=True)

    file_path = os.path.join(upload_folder, file.filename)

    conn = sqlite3.connect(db.db_path)
    cursor = conn.cursor()

    # ✅ 1. Prevent same file name PER USER
    cursor.execute("""
        SELECT id FROM pcap_files WHERE filename = ? AND user_id = ?
    """, (file.filename, request.user.get('uid')))
    already_uploaded = cursor.fetchone()

    if already_uploaded:
        conn.close()
        return jsonify({
            "error": "This file has already been uploaded and analyzed."
        }), 400

    file.save(file_path)

    start_time = datetime.now()

    # 🔧 FIX: ensure PCAP actually contains HTTP packets
    try:
        from scapy.all import rdpcap, TCP, Raw

        packets = rdpcap(file_path)
        http_packets = []

        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode(errors="ignore")
                if "GET " in payload or "POST " in payload:
                    http_packets.append(pkt)

        if not http_packets:
            app.logger.warning("No HTTP requests found in PCAP")

    except Exception as e:
        app.logger.warning("PCAP validation failed: %s", e)

    # 🔧 existing logic continues
    results = process_pcap(file_path)

    end_time = datetime.now()

    processing_time = (end_time - start_time).total_seconds()

    # ✅ 2. Remove duplicate URLs inside same file
    unique_results = {}
    for r in results:
        url = r.get("url")
        if url and url not in unique_results:
            unique_results[url] = r

    results = list(unique_results.values())

    attack_breakdown = {}
    batch_data = []
    malicious_count = 0

    for r in results:
        if not r.get("is_malicious"):
            continue

        url = r.get("url")

        # ✅ 3. Skip if URL already exists in DB for this user
        cursor.execute("""
            SELECT id FROM attacks WHERE url = ? AND user_id = ?
        """, (url, request.user.get('uid')))
        already_exists = cursor.fetchone()

        if already_exists:
            continue

        malicious_count += 1

        attack_type = r.get("attack_type")
        attack_breakdown[attack_type] = attack_breakdown.get(attack_type, 0) + 1

        user_id = request.user.get('uid')
        batch_data.append({
            "timestamp": datetime.now().isoformat(),
            "source_ip": r.get("src_ip", ""),
            "url": url,
            "method": "GET",
            "user_agent": "",
            "attack_type": attack_type,
            "is_malicious": True,
            "is_successful": False,
            "severity": r.get("severity"),
            "confidence": r.get("confidence"),
            "pattern_matched": r.get("pattern_matched", ""),
            "source_type": "pcap",
            "source_file": file.filename,
            "user_id": user_id
        })

    db.insert_batch(batch_data)

    # ✅ 🔥 ALSO SAVE TO FIRESTORE (for Dashboard + Results)
    try:
        fs_collection = (
            firestore_client
            .collection("users")
            .document(request.user.get('uid'))
            .collection("detections")
        )

        for attack in batch_data:
            fs_collection.document().set(attack)

    except Exception as e:
        app.logger.warning("Failed to write PCAP attacks to Firestore: %s", e)

    # 🔥 UPDATED FILE SIZE LOGIC
    file_size_bytes = os.path.getsize(file_path)

    if file_size_bytes < 1024 * 1024:
        file_size = f"{round(file_size_bytes / 1024, 2)} KB"
    else:
        file_size = f"{round(file_size_bytes / (1024 * 1024), 2)} MB"

    upload_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 🔥 UPDATED PROCESSING TIME (show real seconds)
    processing_time_str = f"{processing_time:.2f} sec"

    # ✅ 4. Store structured PCAP summary in DB
    cursor.execute("""
        INSERT INTO pcap_files
        (filename, size_mb, total_urls, attacks_found, upload_time, processing_time, status, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        file.filename,
        file_size,
        len(results),
        malicious_count,
        upload_time,
        processing_time_str,
        "Completed",
        request.user.get('uid')
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "filename": file.filename,
        "file_size_mb": file_size,
        "total_urls": len(results),
        "malicious_detected": malicious_count,
        "processing_time_sec": processing_time,
        "attack_breakdown": attack_breakdown
    })
# =====================================
# EXPORT PCAP FILE ATTACKS (CSV)
# =====================================
# =====================================
# EXPORT PCAP FILE ATTACKS (ALWAYS DOWNLOAD)
# =====================================

@app.route("/api/export-pcap-file", methods=["GET"])
def export_pcap_file():
    filename = request.args.get("file")

    if not filename:
        return jsonify({"error": "File name required"}), 400

    conn = sqlite3.connect(db.db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT timestamp, source_ip, url, attack_type,
               severity, confidence, pattern_matched
        FROM attacks
        WHERE source_type = 'pcap'
        AND source_file = ?
    """, (filename,))

    rows = cursor.fetchall()
    conn.close()

    output = StringIO()

    # Define headers manually (important)
    fieldnames = [
        "timestamp",
        "source_ip",
        "url",
        "attack_type",
        "severity",
        "confidence",
        "pattern_matched"
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    # If no rows → it still creates header-only CSV
    for row in rows:
        writer.writerow(dict(row))

    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}_attacks.csv"
        },
    )
# =====================================
# UPDATED ROUTE → LIST STRUCTURED PCAP FILES
# =====================================

@app.route("/api/pcap-files", methods=["GET"])
@require_auth
def list_uploaded_files():
    conn = sqlite3.connect(db.db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    uid = request.user.get('uid')
    cursor.execute("""
        SELECT filename, size_mb, total_urls, attacks_found,
               upload_time, processing_time, status
        FROM pcap_files
        WHERE user_id = ?
        ORDER BY upload_time DESC
    """, (uid,))

    rows = cursor.fetchall()
    files = [dict(row) for row in rows]

    conn.close()

    return jsonify({"files": files})

# =====================================
# OTHER ROUTES (UNCHANGED)
# =====================================
@app.route("/api/explain", methods=["POST"])
@require_auth
def explain():
    data = request.get_json()

    url = data.get("url")
    attack_type = data.get("attack_type")

    if not url or not attack_type:
        return jsonify({"error": "Missing data"}), 400

    # 🔥 Generate explanation
    explanation = explain_attack(url, attack_type)

    conn = sqlite3.connect(db.db_path)
    cursor = conn.cursor()

    # 🔥 Get latest matching attack row
    uid = request.user.get('uid')
    cursor.execute("""
        SELECT id
        FROM attacks
        WHERE url = ?
        AND attack_type = ?
        AND user_id = ?
        ORDER BY timestamp DESC
        LIMIT 1
    """, (url, attack_type, uid))

    row = cursor.fetchone()

    if row:
        attack_id = row[0]

        cursor.execute("""
            UPDATE attacks
            SET ai_explanation = ?
            WHERE id = ?
        """, (explanation, attack_id))

        conn.commit()

    conn.close()

    return jsonify({
        "explanation": explanation
    })
@app.route("/api/get-explanation", methods=["POST"])
@require_auth
def get_explanation():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL required"}), 400

    conn = sqlite3.connect(db.db_path)
    cursor = conn.cursor()

    uid = request.user.get('uid')
    cursor.execute("""
        SELECT ai_explanation
        FROM attacks
        WHERE url = ?
        AND user_id = ?
        AND ai_explanation IS NOT NULL
        ORDER BY timestamp DESC
        LIMIT 1
    """, (url, uid))

    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify({"explanation": row[0]})
    else:
        return jsonify({"explanation": "No explanation stored for this URL yet."})


# helper used by both /api/attacks and /api/history

def _fetch_user_detections(uid, limit=500):
    col = (
        firestore_client
        .collection("users")
        .document(uid)
        .collection("detections")
    )
    docs = col.order_by("timestamp", direction=firestore.Query.DESCENDING).limit(limit).stream()
    return [doc.to_dict() for doc in docs]


@app.route("/api/attacks", methods=["GET"])
@require_auth
def get_attacks_route():
    # return history from Firestore; kept the same route for compatibility
    uid = request.user.get('uid')
    attacks = _fetch_user_detections(uid)
    return jsonify({"attacks": attacks})


@app.route("/api/history", methods=["GET"])
@require_auth
def get_history_route():
    uid = request.user.get('uid')
    attacks = _fetch_user_detections(uid)
    return jsonify({"attacks": attacks})


@app.route("/api/generate-dataset", methods=["POST"])
@require_auth
def api_generate_dataset():
    data = request.get_json() or {}
    num_records = data.get('num_records', 1500)
    malicious_ratio = data.get('malicious_ratio', 0.5)

    dataset = generator.generate_dataset(num_records=num_records, malicious_ratio=malicious_ratio)
    return jsonify({'success': True, 'records_generated': len(dataset)})


# =============================
# ADMIN LINK HELPERS (DEV)
# =============================

@app.route("/api/gen-reset-link", methods=["POST"])
def gen_reset_link():
    if not firebase_admin:
        return jsonify({"error": "Firebase admin not initialized"}), 500
    data = request.get_json() or {}
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email required"}), 400
    try:
        settings = {
            'url': request.host_url + 'reset-password',
            'handleCodeInApp': False
        }
        link = firebase_auth.generate_password_reset_link(email, action_code_settings=settings)
        return jsonify({"link": link})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/gen-verify-link", methods=["POST"])
@require_auth
def gen_verify_link():
    if not firebase_admin:
        return jsonify({"error": "Firebase admin not initialized"}), 500
    uid = request.user.get('uid')
    try:
        user = firebase_auth.get_user(uid)
        settings = {
            'url': request.host_url + 'login',
            'handleCodeInApp': False
        }
        link = firebase_auth.generate_email_verification_link(user.email, action_code_settings=settings)
        return jsonify({"link": link})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/statistics", methods=["GET"])
@require_auth
def get_statistics_route():
    uid = request.user.get('uid')

    stats = {
        'total_attacks': 0,
        'malicious_attacks': 0,
        'successful_attacks': 0,
        'attack_types': {},
        'severity_distribution': {},
        'weighted_score': 0
    }

    severity_weights = {
        "critical": 1.0,
        "high": 0.75,
        "medium": 0.5,
        "low": 0.25
    }

    col = (
        firestore_client
        .collection("users")
        .document(uid)
        .collection("detections")
    )

    total_weight = 0

    for doc in col.stream():
        data = doc.to_dict()

        stats['total_attacks'] += 1

        if data.get('is_malicious'):
            stats['malicious_attacks'] += 1

        if data.get('is_successful'):
            stats['successful_attacks'] += 1

        at = data.get('attack_type')
        if at:
            stats['attack_types'][at] = stats['attack_types'].get(at, 0) + 1

        sev = data.get('severity')
        if sev:
            stats['severity_distribution'][sev] = (
                stats['severity_distribution'].get(sev, 0) + 1
            )

            total_weight += severity_weights.get(sev.lower(), 0)

    # ✅ Weighted malicious rate
    if stats['total_attacks'] > 0:
        stats['malicious_rate'] = round(
            (total_weight / stats['total_attacks']) * 100, 2
        )
    else:
        stats['malicious_rate'] = 0

    return jsonify(stats)


@app.route("/api/export", methods=["GET"])
@require_auth
def export_data():
    format_type = request.args.get("format", "csv")
    attack_type = request.args.get("attack_type")
    severity = request.args.get("severity")

    uid = request.user.get('uid')

    export_folder = os.path.join(Path(__file__).parent, "exports")
    os.makedirs(export_folder, exist_ok=True)

    filename = os.path.join(export_folder, f"attacks_export.{format_type}")

    conn = sqlite3.connect(db.db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 🔥 Build dynamic query
    query = "SELECT * FROM attacks WHERE user_id = ?"
    params = [uid]

    if attack_type:
        query += " AND attack_type = ?"
        params.append(attack_type)

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()

    if format_type == "json":
        import json
        with open(filename, "w", encoding="utf-8") as f:
            json.dump([dict(row) for row in rows], f, indent=4)
    else:
        import csv
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else [])
            if rows:
                writer.writeheader()
                for row in rows:
                    writer.writerow(dict(row))

    return send_file(filename, as_attachment=True)

@app.route("/")
def home():
    return jsonify({
        "message": "URL Attack Detection API running",
        "available_endpoints": [
            "/api/analyze",
            "/api/attacks",
            "/api/statistics",
            "/api/export",
            "/api/upload-pcap"
        ]
    })


def main():
    parser = argparse.ArgumentParser(description="URL Attack Detection API")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", type=str, default="0.0.0.0")

    args = parser.parse_args()

    print("=" * 60)
    print("URL ATTACK DETECTION BACKEND")
    print("=" * 60)
    print(f"Server running at http://localhost:{args.port}")
    print("=" * 60)

    app.run(debug=True, host=args.host, port=args.port)


if __name__ == "__main__":
    main()