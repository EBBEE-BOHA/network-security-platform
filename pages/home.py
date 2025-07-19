import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from utils.auth_utils import require_auth, get_current_user, init_session_state
from utils.db_utils import get_user_scans
from utils.ml_utils import analyze_threat_patterns, generate_security_recommendations, create_threat_timeline
from utils.visualization_utils import (
    create_threat_distribution_chart, 
    create_timeline_chart, 
    create_detection_trend_chart,
    create_scan_type_comparison
)

def app():
    """Home/Dashboard page."""
    init_session_state()
    
    st.title("🏠 Network Security Dashboard")
    
    # Check authentication
    if not require_auth():
        st.warning("Please login to access the dashboard.")
        st.info("👈 Use the sidebar to navigate to Login/Register")
        return
    
    user = get_current_user()
    st.write(f"Welcome back, **{user['username']}**!")
    
    # Get user's recent scans
    scans = get_user_scans(user['id'], limit=100)
    
    if not scans:
        st.info("No scans found. Start by scanning a file or URL!")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔍 Scan File", type="primary"):
                st.switch_page("pages/scan_file.py")
        with col2:
            if st.button("🌐 Scan URL", type="primary"):
                st.switch_page("pages/scan_url.py")
        return
    
    # Dashboard metrics
    col1, col2, col3, col4 = st.columns(4)
    
    total_scans = len(scans)
    completed_scans = len([s for s in scans if s['status'] == 'completed'])
    malicious_detections = sum(s['malicious_count'] for s in scans if s['malicious_count'] > 0)
    clean_files = len([s for s in scans if s['malicious_count'] == 0 and s['status'] == 'completed'])
    
    with col1:
        st.metric("Total Scans", total_scans)
    
    with col2:
        st.metric("Completed", completed_scans)
    
    with col3:
        st.metric("Threats Detected", malicious_detections, delta_color="inverse")
    
    with col4:
        st.metric("Clean Files", clean_files, delta_color="normal")
    
    # Charts section
    st.markdown("---")
    
    # ML-powered insights
    st.subheader("🧠 AI-Powered Security Insights")
    
    # Analyze threat patterns
    threat_analysis = analyze_threat_patterns(scans)
    
    if threat_analysis['insights']:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🔍 Threat Intelligence:**")
            for insight in threat_analysis['insights']:
                st.info(f"• {insight}")
        
        with col2:
            st.markdown("**💡 Security Recommendations:**")
            recommendations = generate_security_recommendations(
                {'malicious_count': malicious_detections, 'suspicious_count': sum(s['suspicious_count'] for s in scans)},
                scans
            )
            
            for rec in recommendations[:3]:  # Show top 3 recommendations
                priority_color = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(rec['priority'], "ℹ️")
                st.write(f"{priority_color} **{rec['category']}:** {rec['message']}")
    
    # Visualization section
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Threat Distribution")
        
        # Create enhanced pie chart
        threat_chart = create_threat_distribution_chart(scans)
        if threat_chart:
            st.plotly_chart(threat_chart, use_container_width=True)
        else:
            st.info("No data available for threat distribution")
    
    with col2:
        st.subheader("📈 Scan Activity Timeline")
        
        # Create timeline chart
        timeline_chart = create_timeline_chart(scans)
        if timeline_chart:
            st.plotly_chart(timeline_chart, use_container_width=True)
        else:
            st.info("No data available for timeline analysis")
    
    # Additional analytics
    if len(scans) > 10:  # Only show advanced analytics if there's enough data
        st.subheader("📊 Advanced Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Detection trend chart
            trend_chart = create_detection_trend_chart(scans)
            if trend_chart:
                st.plotly_chart(trend_chart, use_container_width=True)
        
        with col2:
            # Scan type comparison
            comparison_chart = create_scan_type_comparison(scans)
            if comparison_chart:
                st.plotly_chart(comparison_chart, use_container_width=True)
        
        # Threat timeline analysis
        timeline_analysis = create_threat_timeline(scans)
        if timeline_analysis['timeline']:
            st.subheader("⏰ Threat Timeline Analysis")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Overall Trend", timeline_analysis['trends']['overall_trend'])
            with col2:
                st.metric("Total Threats", timeline_analysis['trends']['total_threats'])
            with col3:
                st.metric("Avg Threat Rate", f"{timeline_analysis['trends']['average_threat_rate']:.1%}")
    
    # Charts section (keeping original simple charts as fallback)
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Scan Results Distribution")
        
        # Create pie chart for scan results
        if completed_scans > 0:
            threat_counts = {
                'Clean': len([s for s in scans if s['malicious_count'] == 0 and s['status'] == 'completed']),
                'Suspicious': len([s for s in scans if s['suspicious_count'] > 0 and s['malicious_count'] == 0]),
                'Malicious': len([s for s in scans if s['malicious_count'] > 0])
            }
            
            fig_pie = px.pie(
                values=list(threat_counts.values()),
                names=list(threat_counts.keys()),
                color_discrete_map={
                    'Clean': '#00ff00',
                    'Suspicious': '#ffaa00',
                    'Malicious': '#ff0000'
                }
            )
            fig_pie.update_layout(height=300)
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No completed scans to display")
    
    with col2:
        st.subheader("📈 Scan Activity Over Time")
        
        # Create timeline chart
        if scans:
            # Convert scans to DataFrame for easier plotting
            df_scans = pd.DataFrame(scans)
            df_scans['created_at'] = pd.to_datetime(df_scans['created_at'])
            df_scans['date'] = df_scans['created_at'].dt.date
            
            # Group by date
            daily_scans = df_scans.groupby('date').size().reset_index(name='count')
            
            fig_line = px.line(
                daily_scans, 
                x='date', 
                y='count',
                title="Daily Scan Count",
                markers=True
            )
            fig_line.update_layout(height=300)
            st.plotly_chart(fig_line, use_container_width=True)
        else:
            st.info("No scan data to display")
    
    # Recent scans table
    st.markdown("---")
    st.subheader("📋 Recent Scans")
    
    # Display recent scans in a table
    if scans:
        # Prepare data for display
        display_scans = []
        for scan in scans[:10]:  # Show last 10 scans
            status_emoji = {
                'completed': '✅',
                'pending': '⏳',
                'error': '❌'
            }.get(scan['status'], '❓')
            
            threat_level = "🟢 Clean"
            if scan['malicious_count'] > 0:
                threat_level = "🔴 Malicious"
            elif scan['suspicious_count'] > 0:
                threat_level = "🟡 Suspicious"
            
            display_scans.append({
                'Type': scan['scan_type'].title(),
                'Target': scan['target'][:50] + ('...' if len(scan['target']) > 50 else ''),
                'Status': f"{status_emoji} {scan['status'].title()}",
                'Threat Level': threat_level,
                'Detections': f"{scan['malicious_count']}/{scan['malicious_count'] + scan['suspicious_count'] + scan['clean_count']}",
                'Date': scan['created_at'][:19]  # Remove microseconds
            })
        
        df_display = pd.DataFrame(display_scans)
        st.dataframe(df_display, use_container_width=True, hide_index=True)
    else:
        st.info("No recent scans to display")
    
    # Quick actions
    st.markdown("---")
    st.subheader("🚀 Quick Actions")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔍 Scan New File", type="primary", use_container_width=True):
            st.switch_page("pages/scan_file.py")
    
    with col2:
        if st.button("🌐 Scan New URL", type="primary", use_container_width=True):
            st.switch_page("pages/scan_url.py")
    
    with col3:
        if st.button("🔄 Refresh Dashboard", use_container_width=True):
            st.rerun()
    
    # System information
    st.markdown("---")
    st.subheader("ℹ️ System Information")
    
    info_col1, info_col2 = st.columns(2)
    
    with info_col1:
        st.markdown("""
        **Platform Features:**
        - Real-time malware detection
        - URL safety analysis
        - Multi-engine scanning via VirusTotal
        - Secure user authentication
        - Scan history tracking
        """)
    
    with info_col2:
        st.markdown(f"""
        **Your Account:**
        - Username: {user['username']}
        - Role: {user['role'].title()}
        - Total Scans: {total_scans}
        - Account Status: Active ✅
        """)

if __name__ == "__main__":
    app()

