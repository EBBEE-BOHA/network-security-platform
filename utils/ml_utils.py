import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse
import hashlib

def analyze_threat_patterns(scan_results):
    """
    Analyze patterns in scan results to provide intelligent insights.
    
    Args:
        scan_results: List of scan results from database
        
    Returns:
        dict: Analysis insights and recommendations
    """
    if not scan_results:
        return {"insights": [], "recommendations": []}
    
    df = pd.DataFrame(scan_results)
    
    insights = []
    recommendations = []
    
    # Analyze threat trends
    malicious_scans = df[df['malicious_count'] > 0]
    suspicious_scans = df[df['suspicious_count'] > 0]
    
    total_scans = len(df)
    malicious_rate = len(malicious_scans) / total_scans if total_scans > 0 else 0
    suspicious_rate = len(suspicious_scans) / total_scans if total_scans > 0 else 0
    
    # Threat rate analysis
    if malicious_rate > 0.3:
        insights.append(f"High threat detection rate: {malicious_rate:.1%} of scans detected malware")
        recommendations.append("Consider implementing stricter file filtering policies")
    elif malicious_rate > 0.1:
        insights.append(f"Moderate threat detection rate: {malicious_rate:.1%} of scans detected malware")
        recommendations.append("Regular security awareness training recommended")
    else:
        insights.append(f"Low threat detection rate: {malicious_rate:.1%} of scans detected malware")
    
    # File type analysis
    if 'scan_type' in df.columns:
        file_scans = df[df['scan_type'] == 'file']
        url_scans = df[df['scan_type'] == 'url']
        
        if len(file_scans) > 0:
            file_threat_rate = len(file_scans[file_scans['malicious_count'] > 0]) / len(file_scans)
            insights.append(f"File scan threat rate: {file_threat_rate:.1%}")
        
        if len(url_scans) > 0:
            url_threat_rate = len(url_scans[url_scans['malicious_count'] > 0]) / len(url_scans)
            insights.append(f"URL scan threat rate: {url_threat_rate:.1%}")
    
    # Time-based analysis
    if 'created_at' in df.columns:
        df['created_at'] = pd.to_datetime(df['created_at'])
        recent_scans = df[df['created_at'] > datetime.now() - timedelta(days=7)]
        
        if len(recent_scans) > 0:
            recent_threat_rate = len(recent_scans[recent_scans['malicious_count'] > 0]) / len(recent_scans)
            insights.append(f"Recent 7-day threat rate: {recent_threat_rate:.1%}")
            
            if recent_threat_rate > malicious_rate * 1.5:
                recommendations.append("Threat activity has increased recently - consider enhanced monitoring")
    
    return {
        "insights": insights,
        "recommendations": recommendations,
        "threat_statistics": {
            "total_scans": total_scans,
            "malicious_rate": malicious_rate,
            "suspicious_rate": suspicious_rate,
            "clean_rate": 1 - malicious_rate - suspicious_rate
        }
    }

def calculate_risk_score(malicious_count, suspicious_count, total_engines):
    """
    Calculate a risk score based on detection results.
    
    Args:
        malicious_count: Number of engines detecting malware
        suspicious_count: Number of engines detecting suspicious content
        total_engines: Total number of engines that scanned
        
    Returns:
        dict: Risk score and classification
    """
    if total_engines == 0:
        return {"score": 0, "level": "UNKNOWN", "description": "No scan data available"}
    
    # Calculate weighted score
    malicious_weight = 10
    suspicious_weight = 5
    
    raw_score = (malicious_count * malicious_weight + suspicious_count * suspicious_weight)
    max_possible_score = total_engines * malicious_weight
    
    # Normalize to 0-100 scale
    normalized_score = (raw_score / max_possible_score * 100) if max_possible_score > 0 else 0
    
    # Classify risk level
    if normalized_score >= 50:
        level = "CRITICAL"
        description = "High risk - immediate action required"
    elif normalized_score >= 25:
        level = "HIGH"
        description = "Significant risk - caution advised"
    elif normalized_score >= 10:
        level = "MEDIUM"
        description = "Moderate risk - monitor closely"
    elif normalized_score > 0:
        level = "LOW"
        description = "Low risk - minimal concern"
    else:
        level = "MINIMAL"
        description = "No threats detected"
    
    return {
        "score": round(normalized_score, 1),
        "level": level,
        "description": description,
        "detection_ratio": f"{malicious_count + suspicious_count}/{total_engines}"
    }

def analyze_url_characteristics(url):
    """
    Analyze URL characteristics for potential security risks.
    
    Args:
        url: URL to analyze
        
    Returns:
        dict: URL analysis results
    """
    parsed = urlparse(url)
    characteristics = {
        "domain_length": len(parsed.netloc),
        "path_length": len(parsed.path),
        "has_subdomain": len(parsed.netloc.split('.')) > 2,
        "uses_https": parsed.scheme == 'https',
        "has_port": ':' in parsed.netloc,
        "suspicious_keywords": [],
        "risk_factors": []
    }
    
    # Check for suspicious keywords
    suspicious_words = [
        'secure', 'bank', 'paypal', 'amazon', 'microsoft', 'google',
        'login', 'signin', 'account', 'verify', 'update', 'suspended'
    ]
    
    url_lower = url.lower()
    for word in suspicious_words:
        if word in url_lower and word not in parsed.netloc.lower():
            characteristics["suspicious_keywords"].append(word)
    
    # Identify risk factors
    if not characteristics["uses_https"]:
        characteristics["risk_factors"].append("Uses insecure HTTP protocol")
    
    if characteristics["domain_length"] > 50:
        characteristics["risk_factors"].append("Unusually long domain name")
    
    if len(characteristics["suspicious_keywords"]) > 0:
        characteristics["risk_factors"].append("Contains suspicious keywords")
    
    if parsed.netloc.count('-') > 3:
        characteristics["risk_factors"].append("Domain contains many hyphens")
    
    # Calculate suspicion score
    suspicion_score = 0
    suspicion_score += len(characteristics["suspicious_keywords"]) * 2
    suspicion_score += len(characteristics["risk_factors"]) * 3
    suspicion_score += max(0, characteristics["domain_length"] - 20) // 10
    
    characteristics["suspicion_score"] = min(suspicion_score, 10)  # Cap at 10
    
    return characteristics

def generate_security_recommendations(scan_data, user_history):
    """
    Generate personalized security recommendations based on scan data and user history.
    
    Args:
        scan_data: Current scan results
        user_history: User's historical scan data
        
    Returns:
        list: Security recommendations
    """
    recommendations = []
    
    # Analyze current scan
    if scan_data.get('malicious_count', 0) > 0:
        recommendations.append({
            "priority": "HIGH",
            "category": "Immediate Action",
            "message": "Malware detected - do not execute or open this file/visit this URL",
            "action": "Quarantine or delete the file, avoid the website"
        })
    
    if scan_data.get('suspicious_count', 0) > 0:
        recommendations.append({
            "priority": "MEDIUM",
            "category": "Caution",
            "message": "Suspicious content detected - exercise caution",
            "action": "Scan with additional tools, verify source authenticity"
        })
    
    # Analyze user patterns
    if user_history:
        analysis = analyze_threat_patterns(user_history)
        
        if analysis['threat_statistics']['malicious_rate'] > 0.2:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Security Hygiene",
                "message": "High threat detection rate in your scans",
                "action": "Review file sources and browsing habits"
            })
        
        # Add insights as recommendations
        for insight in analysis['insights']:
            recommendations.append({
                "priority": "LOW",
                "category": "Insight",
                "message": insight,
                "action": "Monitor trends and adjust security practices"
            })
    
    # General security recommendations
    recommendations.extend([
        {
            "priority": "LOW",
            "category": "Best Practice",
            "message": "Keep your antivirus software updated",
            "action": "Enable automatic updates for security software"
        },
        {
            "priority": "LOW",
            "category": "Best Practice",
            "message": "Regular system backups are essential",
            "action": "Set up automated backups of important data"
        }
    ])
    
    return recommendations

def detect_file_anomalies(file_info, scan_results):
    """
    Detect anomalies in file characteristics that might indicate threats.
    
    Args:
        file_info: File metadata (name, size, type, etc.)
        scan_results: VirusTotal scan results
        
    Returns:
        dict: Anomaly detection results
    """
    anomalies = []
    risk_score = 0
    
    # File extension analysis
    filename = file_info.get('name', '')
    if filename:
        # Check for double extensions
        if filename.count('.') > 1:
            extensions = filename.split('.')
            if len(extensions) > 2:
                anomalies.append("File has multiple extensions - possible disguised executable")
                risk_score += 3
        
        # Check for suspicious extensions
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.com']
        for ext in suspicious_extensions:
            if filename.lower().endswith(ext):
                anomalies.append(f"Executable file type ({ext}) - exercise caution")
                risk_score += 2
    
    # File size analysis
    file_size = file_info.get('size', 0)
    if file_size > 100 * 1024 * 1024:  # 100MB
        anomalies.append("Large file size - may contain embedded threats")
        risk_score += 1
    elif file_size < 1024 and filename.lower().endswith(('.exe', '.dll')):
        anomalies.append("Unusually small executable - possible packed malware")
        risk_score += 2
    
    # Scan result analysis
    if scan_results:
        stats = scan_results.get('stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        if malicious > 0:
            anomalies.append(f"Detected by {malicious} antivirus engines as malicious")
            risk_score += malicious
        
        if suspicious > 0:
            anomalies.append(f"Flagged by {suspicious} engines as suspicious")
            risk_score += suspicious // 2
    
    return {
        "anomalies": anomalies,
        "risk_score": min(risk_score, 10),  # Cap at 10
        "has_anomalies": len(anomalies) > 0
    }

def create_threat_timeline(scan_history):
    """
    Create a timeline analysis of threats detected over time.
    
    Args:
        scan_history: Historical scan data
        
    Returns:
        dict: Timeline analysis data
    """
    if not scan_history:
        return {"timeline": [], "trends": {}}
    
    df = pd.DataFrame(scan_history)
    df['created_at'] = pd.to_datetime(df['created_at'])
    df['date'] = df['created_at'].dt.date
    
    # Group by date and calculate threat metrics
    daily_stats = df.groupby('date').agg({
        'malicious_count': ['sum', 'count'],
        'suspicious_count': 'sum',
        'id': 'count'
    }).reset_index()
    
    daily_stats.columns = ['date', 'total_malicious', 'scans_with_malicious', 'total_suspicious', 'total_scans']
    daily_stats['threat_rate'] = daily_stats['scans_with_malicious'] / daily_stats['total_scans']
    
    timeline = []
    for _, row in daily_stats.iterrows():
        timeline.append({
            "date": row['date'].strftime('%Y-%m-%d'),
            "total_scans": int(row['total_scans']),
            "threats_detected": int(row['total_malicious']),
            "threat_rate": float(row['threat_rate']),
            "risk_level": "HIGH" if row['threat_rate'] > 0.3 else "MEDIUM" if row['threat_rate'] > 0.1 else "LOW"
        })
    
    # Calculate trends
    if len(timeline) > 1:
        recent_rate = np.mean([t['threat_rate'] for t in timeline[-7:]])  # Last 7 days
        overall_rate = np.mean([t['threat_rate'] for t in timeline])
        
        trend = "INCREASING" if recent_rate > overall_rate * 1.2 else "DECREASING" if recent_rate < overall_rate * 0.8 else "STABLE"
    else:
        trend = "INSUFFICIENT_DATA"
    
    return {
        "timeline": timeline,
        "trends": {
            "overall_trend": trend,
            "total_scans": len(df),
            "total_threats": int(df['malicious_count'].sum()),
            "average_threat_rate": float(df[df['malicious_count'] > 0].shape[0] / len(df)) if len(df) > 0 else 0
        }
    }

