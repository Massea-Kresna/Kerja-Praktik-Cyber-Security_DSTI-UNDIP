import os

content = '''
def get_domains_list(search=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if search:
                cur.execute('SELECT id, domain_name, ip_address, is_active FROM domains WHERE domain_name ILIKE %s ORDER BY domain_name ASC', (f'%{search}%',))
            else:
                cur.execute('SELECT id, domain_name, ip_address, is_active FROM domains ORDER BY domain_name ASC')
            res = cur.fetchall()
            return [dict(row) for row in res]
    except Exception as e:
        print(f'[-] Error get_domains_list: {e}')
        return []
    finally:
        conn.close()

def get_scan_history_list(limit=20):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT sh.id, sh.risk_score, sh.risk_level, sh.scan_date, sh.raw_json, 
                       sh.domain_id, d.domain_name, d.ip_address
                FROM scan_history sh
                JOIN domains d ON sh.domain_id = d.id
                ORDER BY sh.scan_date DESC
                LIMIT %s
            """, (limit,))
            h_res = cur.fetchall()
            if not h_res: return []
            
            h_ids = tuple([h['id'] for h in h_res])
            cur.execute('SELECT history_id, title, severity, check_type, description, recommendation FROM scan_result WHERE history_id IN %s', (h_ids,))
            sr_res = cur.fetchall()
            
            sr_map = {}
            for sr in sr_res:
                hid = sr['history_id']
                if hid not in sr_map: sr_map[hid] = []
                sr_map[hid].append(dict(sr))
                
            result = []
            import json
            for h in h_res:
                row = dict(h)
                row['domains'] = {'domain_name': row.pop('domain_name'), 'ip_address': row.pop('ip_address')}
                if hasattr(row['scan_date'], 'isoformat'):
                    row['scan_date'] = row['scan_date'].isoformat()
                row['vulnerabilities'] = sr_map.get(row['id'], [])
                
                raw_json = row.get('raw_json')
                if isinstance(raw_json, str):
                    try: raw_json = json.loads(raw_json)
                    except: raw_json = []
                if isinstance(raw_json, list):
                    row['vulnerabilities'].extend(raw_json)
                row.pop('raw_json', None)
                result.append(row)
            return result
    except Exception as e:
        print(f'[-] Error get_scan_history_list: {e}')
        return []
    finally:
        conn.close()

def get_vulnerabilities_list(severity=None, limit=50):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            query = """
                SELECT sr.id, sr.severity, sr.check_type, sr.title, sr.description, sr.recommendation, 
                       sr.history_id, sh.scan_date, sh.domain_id, d.domain_name
                FROM scan_result sr
                JOIN scan_history sh ON sr.history_id = sh.id
                JOIN domains d ON sh.domain_id = d.id
            """
            params = []
            if severity:
                query += ' WHERE sr.severity = %s'
                params.append(severity.upper())
            query += ' ORDER BY sh.scan_date DESC LIMIT %s'
            params.append(limit)
            
            cur.execute(query, tuple(params))
            res = cur.fetchall()
            result = []
            for r in res:
                row = dict(r)
                row['scan_history'] = {
                    'scan_date': row.pop('scan_date').isoformat() if hasattr(row.get('scan_date'), 'isoformat') else row.pop('scan_date'),
                    'domain_id': row.pop('domain_id'),
                    'domains': {'domain_name': row.pop('domain_name')}
                }
                result.append(row)
            return result
    except Exception as e:
        print(f'[-] Error get_vulnerabilities_list: {e}')
        return []
    finally:
        conn.close()
'''

with open('db_manager.py', 'a', encoding='utf-8') as f:
    f.write(content)

print('Appended missing functions to db_manager.py')
