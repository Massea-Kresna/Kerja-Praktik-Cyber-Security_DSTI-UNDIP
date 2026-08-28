"""
Centralized Risk Calculator for Pentest Dashboard.
Aligns severity weighting & risk level classification across DB, UI, and Reports.
"""

def calculate_overall_risk(vulnerabilities):
    """
    Calculates overall risk level and score from a list of vulnerability objects.
    
    Returns:
        dict: {
            'risk_level': 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE',
            'risk_score': float (0.0 - 10.0),
            'counts': { 'critical': int, 'high': int, 'medium': int, 'low': int, 'info': int }
        }
    """
    counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }
    
    if not vulnerabilities or not isinstance(vulnerabilities, list):
        return {
            'risk_level': 'SAFE',
            'risk_score': 0.0,
            'counts': counts
        }
        
    for v in vulnerabilities:
        if not isinstance(v, dict):
            continue
        sev = str(v.get('severity') or v.get('risk') or '').upper().strip()
        if sev == 'CRITICAL':
            counts['critical'] += 1
        elif sev == 'HIGH':
            counts['high'] += 1
        elif sev == 'MEDIUM':
            counts['medium'] += 1
        elif sev == 'LOW':
            counts['low'] += 1
        else:
            counts['info'] += 1
            
    # Risk Score calculation (max 10.0)
    score = (counts['critical'] * 4.0) + (counts['high'] * 2.5) + (counts['medium'] * 1.0) + (counts['low'] * 0.3)
    final_score = round(min(score, 10.0), 1)
    
    # Overall Risk Level Determination (Hierarchical Severity Threshold)
    if counts['critical'] > 0:
        risk_level = 'CRITICAL'
    elif counts['high'] > 0:
        risk_level = 'HIGH'
    elif counts['medium'] > 0:
        risk_level = 'MEDIUM'
    elif counts['low'] > 0 or counts['info'] > 0:
        risk_level = 'LOW'
    else:
        risk_level = 'SAFE'
        
    return {
        'risk_level': risk_level,
        'risk_score': final_score,
        'counts': counts
    }
