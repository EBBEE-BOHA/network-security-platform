import streamlit as st
import time
import re
from urllib.parse import urlparse
from utils.auth_utils import require_auth, get_current_user, init_session_state
from utils.virustotal_api import scan_url_with_virustotal, get_url_analysis_report
from utils.db_utils import save_scan_result, update_scan_result

def is_valid_url(url):
    """Validate if the provided string is a valid URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def display_url_scan_results(analysis_data, url):
    """Display the URL scan results in a user-friendly format."""
    if "error" in analysis_data:
        st.error(f"Error: {analysis_data['error']}")
        return
    
    attributes = analysis_data.get("data", {}).get("attributes", {})
    stats = attributes.get("stats", {})
    results = attributes.get("results", {})
    
    # URL information
    st.subheader("🌐 URL Information")
    parsed_url = urlparse(url)
    
    url_info = {
        "URL": url,
        "Domain": parsed_url.netloc,
        "Scheme": parsed_url.scheme,
        "Path": parsed_url.path if parsed_url.path else "/",
    }
    
    for key, value in url_info.items():
        st.write(f"**{key}:** {value}")
    
    # Overall statistics
    st.subheader("📊 Scan Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    
    with col1:
        st.metric("🔴 Malicious", malicious, delta_color="inverse")
    with col2:
        st.metric("🟡 Suspicious", suspicious, delta_color="inverse")
    with col3:
        st.metric("🟢 Safe", harmless + undetected)
    with col4:
        total_engines = malicious + suspicious + undetected + harmless
        st.metric("🔍 Total Engines", total_engines)
    
    # Threat assessment
    st.subheader("🛡️ Safety Assessment")
    
    if malicious > 0:
        st.error(f"⚠️ **DANGEROUS**: {malicious} security engines flagged this URL as malicious!")
        st.error("🚫 **DO NOT VISIT** this website. It may contain malware, phishing content, or other threats.")
        threat_level = "MALICIOUS"
    elif suspicious > 0:
        st.warning(f"⚠️ **CAUTION**: {suspicious} security engines flagged this URL as suspicious.")
        st.warning("⚠️ **Exercise caution** when visiting this website. It may contain potentially harmful content.")
        threat_level = "SUSPICIOUS"
    else:
        st.success("✅ **SAFE**: No threats detected by security engines.")
        st.success("✅ This URL appears to be safe to visit based on current threat intelligence.")
        threat_level = "SAFE"
    
    # Detailed results
    if results:
        st.subheader("🔍 Detailed Engine Results")
        
        # Filter and display results
        malicious_results = []
        suspicious_results = []
        safe_results = []
        
        for engine, result in results.items():
            category = result.get("category", "undetected")
            engine_result = result.get("result", "Clean")
            
            if category == "malicious":
                malicious_results.append({"Engine": engine, "Category": category.title(), "Result": engine_result})
            elif category == "suspicious":
                suspicious_results.append({"Engine": engine, "Category": category.title(), "Result": engine_result})
            else:
                safe_results.append({"Engine": engine, "Category": "Safe", "Result": "Clean"})
        
        # Display in tabs
        tab1, tab2, tab3 = st.tabs([f"🔴 Malicious ({len(malicious_results)})", 
                                   f"🟡 Suspicious ({len(suspicious_results)})", 
                                   f"🟢 Safe ({len(safe_results)})"])
        
        with tab1:
            if malicious_results:
                st.dataframe(malicious_results, use_container_width=True, hide_index=True)
            else:
                st.info("No malicious detections")
        
        with tab2:
            if suspicious_results:
                st.dataframe(suspicious_results, use_container_width=True, hide_index=True)
            else:
                st.info("No suspicious detections")
        
        with tab3:
            if safe_results:
                # Show only first 10 safe results to avoid clutter
                st.dataframe(safe_results[:10], use_container_width=True, hide_index=True)
                if len(safe_results) > 10:
                    st.info(f"... and {len(safe_results) - 10} more engines reported safe")
            else:
                st.info("No safe results")
    
    return {
        "threat_level": threat_level,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "clean_count": harmless + undetected
    }

def app():
    """URL scanning page."""
    init_session_state()
    
    st.title("🌐 URL Scanner")
    st.write("Analyze URLs and websites for phishing, malware, and other security threats.")
    
    # Check authentication
    if not require_auth():
        st.warning("Please login to access URL scanning.")
        st.info("👈 Use the sidebar to navigate to Login/Register")
        return
    
    user = get_current_user()
    
    # URL input section
    st.subheader("🔗 Enter URL to Scan")
    
    url_input = st.text_input(
        "URL to analyze",
        placeholder="https://example.com",
        help="Enter a complete URL including http:// or https://"
    )
    
    # URL validation and scanning
    if url_input:
        if is_valid_url(url_input):
            st.success(f"✅ Valid URL: {url_input}")
            
            # Display URL preview
            st.subheader("🔍 URL Preview")
            parsed = urlparse(url_input)
            
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Domain:** {parsed.netloc}")
                st.write(f"**Protocol:** {parsed.scheme}")
            with col2:
                st.write(f"**Path:** {parsed.path if parsed.path else '/'}")
                st.write(f"**Full URL:** {url_input}")
            
            # Scan button
            if st.button("🚀 Scan URL", type="primary", use_container_width=True):
                # Save initial scan record
                scan_id = save_scan_result(
                    user_id=user['id'],
                    scan_type='url',
                    target=url_input,
                    status='pending'
                )
                
                if scan_id:
                    # Show progress
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    status_text.text("Submitting URL to VirusTotal...")
                    progress_bar.progress(25)
                    
                    # Submit URL to VirusTotal
                    scan_result = scan_url_with_virustotal(url_input)
                    
                    if "error" in scan_result:
                        st.error(f"Scan submission failed: {scan_result['error']}")
                        update_scan_result(scan_id, status='error', result_summary=scan_result['error'])
                        return
                    
                    analysis_id = scan_result.get("data", {}).get("id")
                    if not analysis_id:
                        st.error("Failed to get analysis ID from VirusTotal")
                        update_scan_result(scan_id, status='error', result_summary="No analysis ID received")
                        return
                    
                    # Update scan record with analysis ID
                    update_scan_result(scan_id, analysis_id=analysis_id)
                    
                    status_text.text("URL submitted successfully. Waiting for analysis...")
                    progress_bar.progress(50)
                    
                    # Wait for analysis completion
                    status_text.text("Analysis in progress...")
                    progress_bar.progress(75)
                    
                    # Poll for results
                    max_attempts = 20  # 3-4 minutes max wait time
                    attempt = 0
                    
                    while attempt < max_attempts:
                        analysis_result = get_url_analysis_report(analysis_id)
                        
                        if "error" not in analysis_result:
                            status = analysis_result.get("data", {}).get("attributes", {}).get("status")
                            if status == "completed":
                                break
                        
                        time.sleep(10)  # Wait 10 seconds between checks
                        attempt += 1
                        status_text.text(f"Analysis in progress... (Attempt {attempt}/{max_attempts})")
                    
                    progress_bar.progress(100)
                    status_text.text("Analysis completed!")
                    
                    # Display results
                    if "error" not in analysis_result:
                        st.success("✅ URL scan completed successfully!")
                        
                        # Display results and get summary
                        result_summary = display_url_scan_results(analysis_result, url_input)
                        
                        # Update scan record with final results
                        update_scan_result(
                            scan_id,
                            status='completed',
                            malicious_count=result_summary['malicious_count'],
                            suspicious_count=result_summary['suspicious_count'],
                            clean_count=result_summary['clean_count'],
                            result_summary=result_summary['threat_level']
                        )
                        
                    else:
                        st.error(f"Analysis failed: {analysis_result['error']}")
                        update_scan_result(scan_id, status='error', result_summary=analysis_result['error'])
                else:
                    st.error("Failed to save scan record to database")
        else:
            st.error("❌ Invalid URL format. Please enter a valid URL starting with http:// or https://")
    
    # Common URLs section
    st.markdown("---")
    st.subheader("🔗 Quick Test URLs")
    st.write("Test the scanner with these example URLs:")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Safe URLs (for testing):**
        - `https://www.google.com`
        - `https://www.github.com`
        - `https://www.stackoverflow.com`
        """)
    
    with col2:
        st.markdown("""
        **Test URLs:**
        - `http://malware.testing.google.test/testing/malware/`
        - `https://testsafebrowsing.appspot.com/s/malware.html`
        
        ⚠️ *These are safe test URLs provided by Google for testing purposes*
        """)
    
    # Information section
    st.markdown("---")
    st.subheader("ℹ️ About URL Scanning")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **What we check for:**
        - Phishing websites
        - Malware distribution sites
        - Suspicious redirects
        - Known malicious domains
        - Fraudulent websites
        """)
    
    with col2:
        st.markdown("""
        **Scanning process:**
        - URLs are analyzed by multiple security engines
        - Domain reputation is checked
        - Content is analyzed for threats
        - Results are aggregated and scored
        """)
    
    st.warning("⚠️ **Important:** Even if a URL is marked as safe, always exercise caution when visiting unknown websites. Threat landscapes change rapidly.")

if __name__ == "__main__":
    app()

