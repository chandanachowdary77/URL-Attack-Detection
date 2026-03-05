import sqlite3
import json
from datetime import datetime
import os
from pathlib import Path


class AttackDatabase:
    def __init__(self):
        base_dir = Path(__file__).resolve().parent
        self.db_path = base_dir / "attacks.db"
        self.init_database()

    # ---------------------------------------------------
    # DATABASE INITIALIZATION
    # ---------------------------------------------------

    def init_database(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                url TEXT NOT NULL,
                method TEXT DEFAULT 'GET',
                user_agent TEXT,
                attack_type TEXT NOT NULL,
                is_malicious BOOLEAN NOT NULL,
                is_successful BOOLEAN DEFAULT FALSE,
                severity TEXT DEFAULT 'low',
                confidence REAL DEFAULT 0.0,
                pattern_matched TEXT,
                source_type TEXT DEFAULT 'manual',
                source_file TEXT DEFAULT '',
                user_id TEXT DEFAULT '',
                occurrence_count INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(url, attack_type, source_type, source_file, user_id)
            )
        ''')

        # ✅ Add new column safely (INSIDE FUNCTION)
        try:
            cursor.execute("ALTER TABLE attacks ADD COLUMN ai_explanation TEXT")
        except:
            pass
        # ✅ Add user_id column for per-user data
        try:
            cursor.execute("ALTER TABLE attacks ADD COLUMN user_id TEXT DEFAULT ''")
        except:
            pass

        cursor.execute('''
    CREATE TABLE IF NOT EXISTS pcap_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        size_mb REAL,
        total_urls INTEGER,
        attacks_found INTEGER,
        upload_time TEXT,
        processing_time TEXT,
        status TEXT DEFAULT 'Completed',
        user_id TEXT DEFAULT '',
        UNIQUE(filename, user_id)
    )
''')

        # Safe migration
        cursor.execute("PRAGMA table_info(attacks)")
        existing_columns = [col[1] for col in cursor.fetchall()]

        if "source_type" not in existing_columns:
            cursor.execute("ALTER TABLE attacks ADD COLUMN source_type TEXT DEFAULT 'manual'")

        if "source_file" not in existing_columns:
            cursor.execute("ALTER TABLE attacks ADD COLUMN source_file TEXT DEFAULT ''")

        if "occurrence_count" not in existing_columns:
            cursor.execute("ALTER TABLE attacks ADD COLUMN occurrence_count INTEGER DEFAULT 1")

        # migration for pcap_files user_id
        cursor.execute("PRAGMA table_info(pcap_files)")
        pcap_cols = [col[1] for col in cursor.fetchall()]
        if "user_id" not in pcap_cols:
            try:
                cursor.execute("ALTER TABLE pcap_files ADD COLUMN user_id TEXT DEFAULT ''")
            except:
                pass

        # Indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON attacks(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON attacks(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_type ON attacks(attack_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_successful ON attacks(is_successful)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_type ON attacks(source_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_file ON attacks(source_file)')

        conn.commit()
        conn.close()

    # ---------------------------------------------------
    # INSERT METHODS (UPDATED FOR DUPLICATES)
    # ---------------------------------------------------

    def insert_attack(self, attack_data):
        """Insert or update malicious attack (prevent duplicates)"""

        if not attack_data.get('is_malicious', False):
            return None

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        user_id = attack_data.get('user_id', '')

        try:
            cursor.execute('''
                INSERT INTO attacks (
                    timestamp, source_ip, url, method, user_agent,
                    attack_type, is_malicious, is_successful, severity,
                    confidence, pattern_matched, source_type, source_file,
                    user_id, occurrence_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ''', (
                attack_data.get('timestamp', datetime.now().isoformat()),
                attack_data.get('source_ip', ''),
                attack_data.get('url', ''),
                attack_data.get('method', 'GET'),
                attack_data.get('user_agent', ''),
                attack_data.get('attack_type', 'unknown'),
                1,
                int(attack_data.get('is_successful', False)),
                attack_data.get('severity', 'low'),
                attack_data.get('confidence', 0.0),
                attack_data.get('pattern_matched', ''),
                attack_data.get('source_type', 'manual'),
                attack_data.get('source_file', ''),
                user_id
            ))

            conn.commit()
            return "new"

        except sqlite3.IntegrityError:
            cursor.execute('''
                UPDATE attacks
                SET occurrence_count = occurrence_count + 1,
                    timestamp = ?
                WHERE url = ?
                AND attack_type = ?
                AND source_type = ?
                AND source_file = ?
                AND user_id = ?
            ''', (
                attack_data.get('timestamp', datetime.now().isoformat()),
                attack_data.get('url', ''),
                attack_data.get('attack_type', 'unknown'),
                attack_data.get('source_type', 'manual'),
                attack_data.get('source_file', ''),
                user_id
            ))

            conn.commit()
            return "duplicate"

        finally:
            conn.close()

    def insert_batch(self, attacks_list):
        """Insert multiple malicious attacks with duplicate handling"""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        inserted = 0
        duplicates = 0

        for attack in attacks_list:
            if not attack.get('is_malicious', False):
                continue

            try:
                cursor.execute('''
                    INSERT INTO attacks (
                        timestamp, source_ip, url, method, user_agent,
                        attack_type, is_malicious, is_successful, severity,
                        confidence, pattern_matched, source_type, source_file,
                        user_id, occurrence_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ''', (
                    attack.get('timestamp', datetime.now().isoformat()),
                    attack.get('source_ip', ''),
                    attack.get('url', ''),
                    attack.get('method', 'GET'),
                    attack.get('user_agent', ''),
                    attack.get('attack_type', 'unknown'),
                    1,
                    int(attack.get('is_successful', False)),
                    attack.get('severity', 'low'),
                    attack.get('confidence', 0.0),
                    attack.get('pattern_matched', ''),
                    attack.get('source_type', 'pcap'),
                    attack.get('source_file', ''),
                    attack.get('user_id', '')
                ))
                inserted += 1

            except sqlite3.IntegrityError:
                cursor.execute('''
                    UPDATE attacks
                    SET occurrence_count = occurrence_count + 1,
                        timestamp = ?
                    WHERE url = ?
                    AND attack_type = ?
                    AND source_type = ?
                    AND source_file = ?
                    AND user_id = ?
                ''', (
                    attack.get('timestamp', datetime.now().isoformat()),
                    attack.get('url', ''),
                    attack.get('attack_type', 'unknown'),
                    attack.get('source_type', 'pcap'),
                    attack.get('source_file', ''),
                    attack.get('user_id', '')
                ))
                duplicates += 1

        conn.commit()
        conn.close()

        return {
            "inserted": inserted,
            "duplicates_updated": duplicates
        }

    # ---------------------------------------------------
    # QUERY METHODS
    # ---------------------------------------------------

    def get_attacks(self, limit=100, offset=0, filters=None):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM attacks WHERE is_malicious = 1"
        params = []
        # filter by user if provided
        if filters and filters.get('user_id'):
            query += " AND user_id = ?"
            params.append(filters['user_id'])

        if filters:
            conditions = []

            for key in ['attack_type', 'source_ip', 'is_successful',
                        'severity', 'source_type', 'source_file']:
                if key in filters:
                    conditions.append(f"{key} = ?")
                    params.append(filters[key])

            if conditions:
                query += " AND " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        result = [dict(row) for row in rows]
        conn.close()
        return result

    # ---------------------------------------------------
    # STATISTICS (UPDATED FOR UNIQUE URL COUNT)
    # ---------------------------------------------------

    def get_statistics(self, user_id=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}

        base_query = "SELECT COUNT(DISTINCT url) FROM attacks WHERE is_malicious = 1"
        params = []
        stats = {}

        if user_id:
            base_query += " AND user_id = ?"
            params.append(user_id)

        cursor.execute(base_query, params)
        stats['total_attacks'] = cursor.fetchone()[0]

        # successful attacks
        under_query = "SELECT COUNT(DISTINCT url) FROM attacks WHERE is_successful = 1 AND is_malicious = 1"
        params2 = []
        if user_id:
            under_query += " AND user_id = ?"
            params2.append(user_id)
        cursor.execute(under_query, params2)
        stats['successful_attacks'] = cursor.fetchone()[0]

        # attack types
        types_query = "SELECT attack_type, COUNT(DISTINCT url) FROM attacks WHERE is_malicious = 1"
        params3 = []
        if user_id:
            types_query += " AND user_id = ?"
            params3.append(user_id)
        types_query += " GROUP BY attack_type"
        cursor.execute(types_query, params3)
        stats['attack_types'] = dict(cursor.fetchall())

        # severity distribution
        sev_query = "SELECT severity, COUNT(DISTINCT url) FROM attacks WHERE is_malicious = 1"
        params4 = []
        if user_id:
            sev_query += " AND user_id = ?"
            params4.append(user_id)
        sev_query += " GROUP BY severity"
        cursor.execute(sev_query, params4)
        stats['severity_distribution'] = dict(cursor.fetchall())

        conn.close()
        return stats

    # ---------------------------------------------------
    # EXPORT
    # ---------------------------------------------------

    def export_to_json(self, filename, filters=None):
        attacks = self.get_attacks(limit=10000, filters=filters)
        with open(filename, 'w') as f:
            json.dump(attacks, f, indent=2, default=str)
        return len(attacks)

    def export_to_csv(self, filename, filters=None):
        import csv

        attacks = self.get_attacks(limit=10000, filters=filters)
        if not attacks:
            return 0

        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=attacks[0].keys())
            writer.writeheader()
            writer.writerows(attacks)

        return len(attacks)