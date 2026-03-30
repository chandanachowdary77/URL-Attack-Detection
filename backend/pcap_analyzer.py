import os
import pyshark
from attack_detector import URLAttackDetector
from database import AttackDatabase
from datetime import datetime
from urllib.parse import unquote

detector = URLAttackDetector()
db = AttackDatabase()


def process_pcap(file_path):
    results = []
    db_records = []

    filename = os.path.basename(file_path)

    # =====================================================
    # TEXT FILE MODE (Simulated URLs)
    # =====================================================
    if file_path.endswith(".txt"):
        with open(file_path, "r") as f:
            for line in f:
                url = line.strip()
                if not url:
                    continue

                # 🔧 decode URL if encoded
                decoded_url = unquote(url)

                analysis = detector.analyze_url(decoded_url)

                is_successful = False

                if analysis["is_malicious"]:
                    db_records.append({
                        "timestamp": datetime.now().isoformat(),
                        "source_ip": "0.0.0.0",
                        "url": decoded_url,
                        "method": "GET",
                        "user_agent": "",
                        "attack_type": analysis["primary_attack_type"],
                        "is_malicious": True,
                        "is_successful": is_successful,
                        "severity": analysis["severity"],
                        "confidence": analysis["confidence"],
                        "pattern_matched": analysis["attacks_detected"][0]["pattern_matched"]
                        if analysis["attacks_detected"] else "",
                        "source_type": "pcap",
                        "source_file": filename
                    })

                results.append({
                    "timestamp": datetime.now().isoformat(),
                    "source_ip": "0.0.0.0",
                    "url": decoded_url,
                    "method": "GET",
                    "user_agent": "",
                    "attack_type": analysis["primary_attack_type"],
                    "is_malicious": analysis["is_malicious"],
                    "is_successful": is_successful,
                    "severity": analysis["severity"],
                    "confidence": analysis["confidence"]
                })

        if db_records:
            db.insert_batch(db_records)

        return results

    # =====================================================
    # REAL PCAP MODE
    # =====================================================
    try:
        cap = pyshark.FileCapture(file_path, display_filter='http')

        for packet in cap:
            if hasattr(packet, 'http'):

                uri = getattr(packet.http, 'request_uri', '')

                if not uri:
                    uri = getattr(packet.http, 'request_uri_path', '')

                if not uri:
                    uri = getattr(packet.http, 'request_full_uri', '')

                host = getattr(packet.http, 'host', '')

                if uri.startswith("http"):
                    full_url = uri
                else:
                    full_url = f"http://{host}{uri}"

                # 🔧 CRITICAL FIX: decode URL
                decoded_url = unquote(full_url)

                analysis = detector.analyze_url(decoded_url)

                is_successful = False
                if hasattr(packet.http, "response_code"):
                    response_code = packet.http.response_code
                    if response_code == "200" and analysis["severity"] == "critical":
                        is_successful = True

                if analysis["is_malicious"]:
                    db_records.append({
                        "timestamp": str(packet.sniff_time),
                        "source_ip": packet.ip.src if hasattr(packet, 'ip') else "",
                        "url": decoded_url,
                        "method": getattr(packet.http, 'request_method', 'GET'),
                        "user_agent": "",
                        "attack_type": analysis["primary_attack_type"],
                        "is_malicious": True,
                        "is_successful": is_successful,
                        "severity": analysis["severity"],
                        "confidence": analysis["confidence"],
                        "pattern_matched": analysis["attacks_detected"][0]["pattern_matched"]
                        if analysis["attacks_detected"] else "",
                        "source_type": "pcap",
                        "source_file": filename
                    })

                results.append({
                    "timestamp": str(packet.sniff_time),
                    "source_ip": packet.ip.src if hasattr(packet, 'ip') else "",
                    "url": decoded_url,
                    "method": getattr(packet.http, 'request_method', 'GET'),
                    "user_agent": "",
                    "attack_type": analysis["primary_attack_type"],
                    "is_malicious": analysis["is_malicious"],
                    "is_successful": is_successful,
                    "severity": analysis["severity"],
                    "confidence": analysis["confidence"]
                })

        cap.close()

        if db_records:
            db.insert_batch(db_records)

    except Exception as e:
        print("PCAP Error:", e)

    return results