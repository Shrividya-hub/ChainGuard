def calculate_risk(vulnerabilities):
    if not vulnerabilities:
        return "LOW"
    
    if len(vulnerabilities) >= 2:
        return "HIGH"
    
    return "MEDIUM"