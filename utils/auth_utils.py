import streamlit as st
from utils.db_utils import authenticate_user, create_user, get_user_by_id

def init_session_state():
    """Initialize session state variables for authentication."""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user' not in st.session_state:
        st.session_state.user = None

def login_user(username, password):
    """
    Login a user and update session state.
    
    Args:
        username: User's username
        password: User's password
        
    Returns:
        bool: True if login successful, False otherwise
    """
    user = authenticate_user(username, password)
    if user:
        st.session_state.authenticated = True
        st.session_state.user = user
        return True
    return False

def logout_user():
    """Logout the current user."""
    st.session_state.authenticated = False
    st.session_state.user = None

def register_user(username, email, password, confirm_password):
    """
    Register a new user.
    
    Args:
        username: Desired username
        email: User's email
        password: Desired password
        confirm_password: Password confirmation
        
    Returns:
        dict: Result of registration attempt
    """
    # Validate inputs
    if not username or not email or not password:
        return {"success": False, "message": "All fields are required"}
    
    if len(username) < 3:
        return {"success": False, "message": "Username must be at least 3 characters long"}
    
    if len(password) < 6:
        return {"success": False, "message": "Password must be at least 6 characters long"}
    
    if password != confirm_password:
        return {"success": False, "message": "Passwords do not match"}
    
    if "@" not in email:
        return {"success": False, "message": "Please enter a valid email address"}
    
    # Create user in database
    return create_user(username, email, password)

def is_authenticated():
    """Check if user is authenticated."""
    return st.session_state.get('authenticated', False)

def get_current_user():
    """Get current authenticated user."""
    return st.session_state.get('user', None)

def require_auth():
    """
    Decorator-like function to require authentication.
    Returns True if user is authenticated, False otherwise.
    """
    init_session_state()
    return is_authenticated()

def is_admin():
    """Check if current user is an admin."""
    user = get_current_user()
    return user and user.get('role') == 'admin'

def check_permission(required_role='user'):
    """
    Check if current user has required permission level.
    
    Args:
        required_role: Required role ('user' or 'admin')
        
    Returns:
        bool: True if user has permission, False otherwise
    """
    if not is_authenticated():
        return False
    
    user = get_current_user()
    if not user:
        return False
    
    user_role = user.get('role', 'user')
    
    if required_role == 'admin':
        return user_role == 'admin'
    else:
        return user_role in ['user', 'admin']

