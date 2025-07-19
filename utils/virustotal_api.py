import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

def upload_file_to_virustotal(file_content):
    """
    Upload a file to VirusTotal for analysis.
    
    Args:
        file_content: The file content as bytes
        
    Returns:
        dict: Response from VirusTotal API containing analysis ID
    """
    url = f"{VIRUSTOTAL_BASE_URL}/files"
    headers = {
        "X-Apikey": VIRUSTOTAL_API_KEY
    }
    
    files = {"file": file_content}
    
    try:
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def get_file_analysis_report(analysis_id):
    """
    Get the analysis report for a file.
    
    Args:
        analysis_id: The analysis ID returned from file upload
        
    Returns:
        dict: Analysis report from VirusTotal
    """
    url = f"{VIRUSTOTAL_BASE_URL}/analyses/{analysis_id}"
    headers = {
        "X-Apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def scan_url_with_virustotal(url_to_scan):
    """
    Submit a URL to VirusTotal for analysis.
    
    Args:
        url_to_scan: The URL to be scanned
        
    Returns:
        dict: Response from VirusTotal API containing analysis ID
    """
    url = f"{VIRUSTOTAL_BASE_URL}/urls"
    headers = {
        "X-Apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    data = {"url": url_to_scan}
    
    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def get_url_analysis_report(analysis_id):
    """
    Get the analysis report for a URL.
    
    Args:
        analysis_id: The analysis ID returned from URL submission
        
    Returns:
        dict: Analysis report from VirusTotal
    """
    url = f"{VIRUSTOTAL_BASE_URL}/analyses/{analysis_id}"
    headers = {
        "X-Apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def wait_for_analysis_completion(analysis_id, max_wait_time=300, check_interval=10):
    """
    Wait for analysis to complete by polling the analysis endpoint.
    
    Args:
        analysis_id: The analysis ID to check
        max_wait_time: Maximum time to wait in seconds (default: 5 minutes)
        check_interval: Time between checks in seconds (default: 10 seconds)
        
    Returns:
        dict: Final analysis report or error
    """
    start_time = time.time()
    
    while time.time() - start_time < max_wait_time:
        report = get_file_analysis_report(analysis_id)
        
        if "error" in report:
            return report
            
        if report.get("data", {}).get("attributes", {}).get("status") == "completed":
            return report
            
        time.sleep(check_interval)
    
    return {"error": "Analysis timed out"}

def get_file_hash_report(file_hash):
    """
    Get analysis report for a file using its hash.
    
    Args:
        file_hash: SHA256, SHA1, or MD5 hash of the file
        
    Returns:
        dict: Analysis report from VirusTotal
    """
    url = f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}"
    headers = {
        "X-Apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def get_ip_report(ip_address):
    """
    Get analysis report for an IP address.
    
    Args:
        ip_address: The IP address to analyze
        
    Returns:
        dict: Analysis report from VirusTotal
    """
    url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip_address}"
    headers = {
        "X-Apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def get_domain_report(domain):
    """
    Get analysis report for a domain.
    
    Args:
        domain: The domain to analyze
        
    Returns:
        dict: Analysis report from VirusTotal
    """
    url = f"{VIRUSTOTAL_BASE_URL}/domains/{domain}"
    headers = {
        "X-Apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

