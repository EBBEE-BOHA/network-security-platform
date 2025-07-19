import streamlit as st
from pages import home, scan_file, scan_url, auth

st.set_page_config(layout="wide")

def main():
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Home", "Scan File", "Scan URL", "Login/Register"])

    if page == "Home":
        home.app()
    elif page == "Scan File":
        scan_file.app()
    elif page == "Scan URL":
        scan_url.app()
    elif page == "Login/Register":
        auth.app()

if __name__ == "__main__":
    main()


