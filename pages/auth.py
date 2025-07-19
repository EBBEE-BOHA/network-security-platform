import streamlit as st
from utils.auth_utils import login_user, register_user, logout_user, is_authenticated, get_current_user, init_session_state

def app():
    """Authentication page - Login and Registration."""
    init_session_state()
    
    st.title("🔐 Authentication")
    
    # If user is already authenticated, show logout option
    if is_authenticated():
        user = get_current_user()
        st.success(f"Welcome back, {user['username']}!")
        st.write(f"**Role:** {user['role'].title()}")
        st.write(f"**Email:** {user['email']}")
        
        if st.button("Logout", type="primary"):
            logout_user()
            st.rerun()
        return
    
    # Authentication tabs
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        st.subheader("Login to Your Account")
        
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit_login = st.form_submit_button("Login", type="primary")
            
            if submit_login:
                if username and password:
                    if login_user(username, password):
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error("Invalid username or password")
                else:
                    st.error("Please enter both username and password")
    
    with tab2:
        st.subheader("Create New Account")
        
        with st.form("register_form"):
            reg_username = st.text_input("Choose Username")
            reg_email = st.text_input("Email Address")
            reg_password = st.text_input("Choose Password", type="password")
            reg_confirm_password = st.text_input("Confirm Password", type="password")
            submit_register = st.form_submit_button("Register", type="primary")
            
            if submit_register:
                result = register_user(reg_username, reg_email, reg_password, reg_confirm_password)
                if result["success"]:
                    st.success(result["message"])
                    st.info("You can now login with your credentials!")
                else:
                    st.error(result["message"])
    
    # Information section
    st.markdown("---")
    st.markdown("""
    ### About This System
    
    This is a **Network Security Platform** powered by machine learning and integrated with the VirusTotal API for real-time threat detection.
    
    **Features:**
    - 🔍 File scanning and malware detection
    - 🌐 URL analysis and phishing detection
    - 📊 Real-time threat intelligence
    - 👥 User management and role-based access
    - 📈 Scan history and analytics
    
    **Getting Started:**
    1. Register for a new account or login with existing credentials
    2. Navigate to the scanning pages to analyze files or URLs
    3. View your scan history and results on the dashboard
    """)

if __name__ == "__main__":
    app()

