import re
import urllib.parse
from datetime import datetime
from ml_model import predict_url


class URLAttackDetector:
    def __init__(self):

        # -----------------------------
        # SQL Injection (Advanced)
        # -----------------------------
        self.sql_patterns = [
            r"('|--|#|/\*)",
            r"union\s+all?\s+select",
            r"select\s+.*\s+from",
            r"insert\s+into",
            r"delete\s+from",
            r"drop\s+table",
            r"update\s+.*\s+set",
            r"exec\s+xp_",
            r"benchmark\(",
            r"sleep\(",
            r"or\s+1=1",
            r"and\s+1=1",
            r"or\s+\d+=\d+"
        ]

        # -----------------------------
        # XSS
        # -----------------------------
        self.xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"alert\(",
            r"document\.cookie",
            r"<svg.*?>",
            r"<iframe.*?>",
            r"eval\(",
            r"innerhtml"
        ]

        # -----------------------------
        # Directory Traversal
        # -----------------------------
        self.traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"/etc/passwd",
            r"boot\.ini",
            r"windows/system32",
            r"etc/shadow"
        ]

        # -----------------------------
        # Command Injection
        # -----------------------------
        self.command_patterns = [
    r"cmd=",
    r"exec=",
    r"run=",
    r";\s*(cat|ls|dir|type|ping|wget|curl|whoami|id)",
    r"\|\s*(nc|netcat|telnet)",
    r"&&\s*(whoami|id|uname)",
    r"`.*`",
    r"\$\(.*\)",
    r"whoami",
    r"id",
    r"uname"
]

        # -----------------------------
        # SSRF
        # -----------------------------
        self.ssrf_patterns = [
            r"127\.0\.0\.1",
            r"localhost",
            r"169\.254\.169\.254",
            r"192\.168\.",
            r"10\.\d+\.",
            r"172\.(1[6-9]|2\d|3[0-1])\.",
            r"file://",
            r"gopher://"
        ]

        # -----------------------------
        # LFI / RFI
        # -----------------------------
        self.lfi_rfi_patterns = [
            r"php://input",
            r"php://filter",
            r"data://",
            r"expect://",
            r"input=",
            r"http://.*\.php",
            r"https://.*\.php"
        ]

        # -----------------------------
        # Brute Force
        # -----------------------------
        self.bruteforce_patterns = [
            r"password=",
            r"username=",
            r"login",
            r"signin",
            r"auth"
        ]

        # -----------------------------
        # HTTP Parameter Pollution
        # -----------------------------
        self.hpp_patterns = [
            r"\?.*&.*&.*=",
            r"=\w+&\w+="
        ]

        # -----------------------------
        # XXE
        # -----------------------------
        self.xxe_patterns = [
            r"<!doctype\s+",
            r"<!entity\s+",
            r"system\s+\"http",
            r"file:///etc/passwd"
        ]

        # -----------------------------
        # Web Shell
        # -----------------------------
        self.webshell_patterns = [
            r"cmd\.jsp",
            r"backdoor\.asp",
            r"shell\.php",
            r"c99\.php",
            r"r57\.php",
            r"webshell",
            r"\.aspx\?cmd=",
            r"\.php\?cmd="
        ]

        # -----------------------------
        # Typosquatting
        # -----------------------------
        self.typosquatting_patterns = [
            r"go0gle\.com",
            r"faceb00k\.com",
            r"paypa1\.com",
            r"amaz0n\.com",
            r"micr0soft\.com"
        ]

    # ---------------------------------
    # Pattern Matching
    # ---------------------------------

    def detect_pattern(self, url, patterns):
        decoded_url = urllib.parse.unquote(url).lower()
        for pattern in patterns:
            if re.search(pattern, decoded_url, re.IGNORECASE):
                return True, pattern
        return False, None

    # ---------------------------------
    # Main Analyzer (Hybrid System)
    # ---------------------------------

    def analyze_url(self, url):
        # 🔧 Normalize URL before analysis
        url = urllib.parse.unquote(url)  # decode %20 etc
        url = url.lower()

        results = {
            "url": url,
            "is_malicious": False,
            "primary_attack_type": None,
            "attacks_detected": [],
            "severity": "none",
            "confidence": 0.0
        }

        attack_map = {
            "sql_injection": self.sql_patterns,
            "xss": self.xss_patterns,
            "directory_traversal": self.traversal_patterns,
            "command_injection": self.command_patterns,
            "ssrf": self.ssrf_patterns,
            "lfi_rfi": self.lfi_rfi_patterns,
            "bruteforce_attempt": self.bruteforce_patterns,
            "http_parameter_pollution": self.hpp_patterns,
            "xxe": self.xxe_patterns,
            "webshell_upload": self.webshell_patterns,
            "typosquatting": self.typosquatting_patterns
        }

        total_confidence = 0

        # -----------------------------
        # REGEX Detection
        # -----------------------------
        for attack_name, patterns in attack_map.items():
            detected, pattern = self.detect_pattern(url, patterns)
            if detected:
                results["attacks_detected"].append({
                    "type": attack_name,
                    "pattern_matched": pattern,
                    "confidence": 0.9
                })
                total_confidence += 0.9

        # -----------------------------
        # ML Detection (Duplicate Merge)
        # -----------------------------
        ml_prediction, ml_confidence = predict_url(url)

        if ml_prediction not in ["none", "safe"]:

            existing_attack = next(
                (a for a in results["attacks_detected"] if a["type"] == ml_prediction),
                None
            )

            if existing_attack:
                existing_attack["confidence"] = max(
                    existing_attack["confidence"], ml_confidence
                )
            else:
                results["attacks_detected"].append({
                    "type": ml_prediction,
                    "pattern_matched": "ML_model_detection",
                    "confidence": ml_confidence
                })

            total_confidence += ml_confidence

        # -----------------------------
        # Final Decision
        # -----------------------------
        if results["attacks_detected"]:
            results["is_malicious"] = True
            results["primary_attack_type"] = results["attacks_detected"][0]["type"]
            results["confidence"] = min(total_confidence, 1.0)
            results["severity"] = self.calculate_severity(results["attacks_detected"])

        return results

    # ---------------------------------
    # Severity Calculation
    # ---------------------------------

    def calculate_severity(self, attacks):

        severity_map = {
            "sql_injection": 5,
            "command_injection": 5,
            "xxe": 5,
            "webshell_upload": 5,
            "ssrf": 4,
            "lfi_rfi": 4,
            "directory_traversal": 3,
            "xss": 3,
            "bruteforce_attempt": 2,
            "http_parameter_pollution": 2,
            "typosquatting": 3
        }

        max_severity = max(
            [severity_map.get(attack["type"], 1) for attack in attacks]
        )

        if max_severity >= 5:
            return "critical"
        elif max_severity >= 4:
            return "high"
        elif max_severity >= 3:
            return "medium"
        else:
            return "low"

    # ---------------------------------
    # Format for Database
    # ---------------------------------

    def format_for_database(self, analysis_result, source_ip="unknown",
                            method="GET", user_agent="",
                            is_successful=False):

        if not analysis_result.get("is_malicious"):
            return None

        primary_attack = analysis_result.get("primary_attack_type")

        pattern_matched = ""
        if analysis_result.get("attacks_detected"):
            pattern_matched = analysis_result["attacks_detected"][0].get(
                "pattern_matched", ""
            )

        return {
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "url": analysis_result.get("url", ""),
            "method": method,
            "user_agent": user_agent,
            "attack_type": primary_attack,
            "is_malicious": True,
            "is_successful": is_successful,
            "severity": analysis_result.get("severity", "low"),
            "confidence": analysis_result.get("confidence", 0.0),
            "pattern_matched": pattern_matched
        }