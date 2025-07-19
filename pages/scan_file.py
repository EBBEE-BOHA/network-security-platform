import streamlit as st
import hashlib
import time
from utils.auth_utils import require_auth, get_current_user, init_session_state
from utils.virustotal_api import upload_file_to_virustotal, get_file_analysis_report, wait_for_analysis_completion
from utils.db_utils import save_scan_result, update_scan_result, calculate_file_hash
from utils.ml_utils import calculate_risk_score, detect_file_anomalies, generate_security_recommendations
from utils.visualization_utils import create_risk_gauge, create_engine_comparison_chart

def display_scan_results(analysis_data, file_info=None):
    """Display the scan results in a user-friendly format with ML analysis."""
    if "error" in analysis_data:
        st.error(f"Error: {analysis_data['error']}")
        return
    
    attributes = analysis_data.get("data", {}).get("attributes", {})
    stats = attributes.get("stats", {})
    results = attributes.get("results", {})
    
    # Overall statistics
    st.subheader("📊 Scan Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    total_engines = malicious + suspicious + undetected + harmless
    
    with col1:
        st.metric("🔴 Malicious", malicious, delta_color="inverse")
    with col2:
        st.metric("🟡 Suspicious", suspicious, delta_color="inverse")
    with col3:
        st.metric("🟢 Clean", harmless + undetected)
    with col4:
        st.metric("🔍 Total Engines", total_engines)
    
    # ML-powered risk analysis
    st.subheader("🧠 AI Risk Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Calculate and display risk score
        risk_analysis = calculate_risk_score(malicious, suspicious, total_engines)
        
        st.markdown(f"**Risk Level:** {risk_analysis['level']}")
        st.markdown(f"**Risk Score:** {risk_analysis['score']}/100")
        st.markdown(f"**Detection Ratio:** {risk_analysis['detection_ratio']}")
        st.markdown(f"**Assessment:** {risk_analysis['description']}")
        
        # Risk gauge chart
        risk_gauge = create_risk_gauge(risk_analysis['score'], 100)
        if risk_gauge:
            st.plotly_chart(risk_gauge, use_container_width=True)
    
    with col2:
        # File anomaly detection
        if file_info:
            anomaly_analysis = detect_file_anomalies(file_info, {'stats': stats})
            
            st.markdown("**🔍 File Analysis:**")
            if anomaly_analysis['has_anomalies']:
                st.warning(f"**Anomalies Detected** (Risk Score: {anomaly_analysis['risk_score']}/10)")
                for anomaly in anomaly_analysis['anomalies']:
                    st.write(f"⚠️ {anomaly}")
            else:
                st.success("✅ No file anomalies detected")
        
        # Engine comparison chart
        engine_chart = create_engine_comparison_chart(analysis_data)
        if engine_chart:
            st.plotly_chart(engine_chart, use_container_width=True)
    
    # Threat assessment
    st.subheader("🛡️ Threat Assessment")
    
    if malicious > 0:
        st.error(f"⚠️ **HIGH RISK**: {malicious} security engines detected this file as malicious!")
        threat_level = "MALICIOUS"
        
        # Generate specific recommendations for malicious files
        st.subheader("🚨 Immediate Actions Required")
        st.error("🚫 **DO NOT EXECUTE** this file")
        st.error("🗑️ **DELETE** or quarantine this file immediately")
        st.error("🔍 **SCAN** your system for potential infections")
        
    elif suspicious > 0:
        st.warning(f"⚠️ **MEDIUM RISK**: {suspicious} security engines flagged this file as suspicious.")
        threat_level = "SUSPICIOUS"
        
        st.subheader("⚠️ Recommended Actions")
        st.warning("🔍 **INVESTIGATE** further before executing")
        st.warning("🛡️ **SCAN** with additional security tools")
        st.warning("📋 **VERIFY** the file source and authenticity")
        
    else:
        st.success("✅ **LOW RISK**: No threats detected by security engines.")
        threat_level = "CLEAN"
        
        st.subheader("✅ File Appears Safe")
        st.success("🟢 No malicious content detected")
        st.info("💡 Always verify file sources and keep security software updated")
    
    # Security recommendations
    st.subheader("💡 Security Recommendations")
    recommendations = generate_security_recommendations(
        {'malicious_count': malicious, 'suspicious_count': suspicious},
        []  # No user history in this context
    )
    
    for rec in recommendations[:5]:  # Show top 5 recommendations
        priority_color = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(rec['priority'], "ℹ️")
        with st.expander(f"{priority_color} {rec['category']}: {rec['message']}"):
            st.write(f"**Action:** {rec['action']}")
    
    # Detailed results
    if results:
        st.subheader("🔍 Detailed Engine Results")
        
        # Filter and display results
        malicious_results = []
        suspicious_results = []
        clean_results = []
        
        for engine, result in results.items():
            category = result.get("category", "undetected")
            engine_result = result.get("result", "Clean")
            
            if category == "malicious":
                malicious_results.append({"Engine": engine, "Result": engine_result})
            elif category == "suspicious":
                suspicious_results.append({"Engine": engine, "Result": engine_result})
            else:
                clean_results.append({"Engine": engine, "Result": "Clean"})
        
        # Display in tabs
        tab1, tab2, tab3 = st.tabs([f"🔴 Malicious ({len(malicious_results)})", 
                                   f"🟡 Suspicious ({len(suspicious_results)})", 
                                   f"🟢 Clean ({len(clean_results)})"])
        
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
            if clean_results:
                # Show only first 10 clean results to avoid clutter
                st.dataframe(clean_results[:10], use_container_width=True, hide_index=True)
                if len(clean_results) > 10:
                    st.info(f"... and {len(clean_results) - 10} more engines reported clean")
            else:
                st.info("No clean results")
    
    return {
        "threat_level": threat_level,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "clean_count": harmless + undetected,
        "risk_score": risk_analysis['score']
    }

def app():
    """File scanning page."""
    init_session_state()
    
    st.title("🔍 File Scanner")
    st.write("Upload files to scan for malware and threats using VirusTotal's multi-engine analysis.")
    
    # Check authentication
    if not require_auth():
        st.warning("Please login to access file scanning.")
        st.info("👈 Use the sidebar to navigate to Login/Register")
        return
    
    user = get_current_user()
    
    # File upload section
    st.subheader("📁 Upload File for Scanning")
    
    uploaded_file = st.file_uploader(
        "Choose a file to scan",
        type=None,  # Allow all file types
        help="Upload any file to scan for malware. Maximum file size: 200MB"
    )
    
    if uploaded_file is not None:
        # Display file information
        st.subheader("📋 File Information")
        
        file_details = {
            "Filename": uploaded_file.name,
            "File Size": f"{uploaded_file.size:,} bytes ({uploaded_file.size / (1024*1024):.2f} MB)",
            "File Type": uploaded_file.type if uploaded_file.type else "Unknown"
        }
        
        col1, col2 = st.columns(2)
        with col1:
            for key, value in file_details.items():
                st.write(f"**{key}:** {value}")
        
        # Calculate file hash
        file_content = uploaded_file.read()
        file_hash = calculate_file_hash(file_content)
        
        with col2:
            st.write(f"**SHA256 Hash:** `{file_hash}`")
            st.write(f"**Upload Time:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Scan button
        if st.button("🚀 Start Scan", type="primary", use_container_width=True):
            # Save initial scan record
            scan_id = save_scan_result(
                user_id=user['id'],
                scan_type='file',
                target=uploaded_file.name,
                file_hash=file_hash,
                status='pending'
            )
            
            if scan_id:
                # Show progress
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                status_text.text("Uploading file to VirusTotal...")
                progress_bar.progress(25)
                
                # Upload file to VirusTotal
                upload_result = upload_file_to_virustotal(file_content)
                
                if "error" in upload_result:
                    st.error(f"Upload failed: {upload_result['error']}")
                    update_scan_result(scan_id, status='error', result_summary=upload_result['error'])
                    return
                
                analysis_id = upload_result.get("data", {}).get("id")
                if not analysis_id:
                    st.error("Failed to get analysis ID from VirusTotal")
                    update_scan_result(scan_id, status='error', result_summary="No analysis ID received")
                    return
                
                # Update scan record with analysis ID
                # 
                update_scan_result(scan_id, analysis_id=analysis_id)
                
                status_text.text("File uploaded successfully. Waiting for analysis...")
                progress_bar.progress(50)
                
                # Wait for analysis completion
                status_text.text("Analysis in progress... This may take a few minutes.")
                progress_bar.progress(75)
                
                # Poll for results
                max_attempts = 30  # 5 minutes max wait time
                attempt = 0
                
                while attempt < max_attempts:
                    analysis_result = get_file_analysis_report(analysis_id)
                    
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
                    st.success("✅ Scan completed successfully!")
                    
                    # Display results and get summary
                    result_summary = display_scan_results(analysis_result, {
                        'name': uploaded_file.name,
                        'size': uploaded_file.size,
                        'type': uploaded_file.type
                    })
                    
                    # Update scan record with final results
                    update_scan_result(
                        scan_id,
                       # analysis_id,
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
    
    # Information section
    st.markdown("---")
    st.subheader("ℹ️ About File Scanning")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **What we scan for:**
        - Viruses and malware
        - Trojans and backdoors
        - Ransomware
        - Spyware and adware
        - Potentially unwanted programs (PUPs)
        """)
    
    with col2:
        st.markdown("""
        **Scanning process:**
        - Files are analyzed by 70+ antivirus engines
        - Results are aggregated and scored
        - Detailed reports show engine-specific findings
        - All scans are logged for your reference
        """)
    
    st.info("💡 **Tip:** Large files may take longer to analyze. The system will wait up to 5 minutes for results.")

if __name__ == "__main__":
    app()

