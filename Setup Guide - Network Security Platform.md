# Setup Guide - Network Security Platform

This comprehensive guide will walk you through setting up the Network Security Platform on Windows, macOS, and Linux systems.

## 📋 System Requirements

### Minimum Requirements
- **Operating System**: Windows 10/11, macOS 10.14+, or Linux (Ubuntu 18.04+)
- **Python**: Version 3.7 or higher
- **RAM**: 512MB available memory
- **Storage**: 100MB free space
- **Internet**: Stable connection for API calls

### Recommended Requirements
- **Python**: Version 3.9 or higher
- **RAM**: 1GB or more available memory
- **Storage**: 1GB free space (for scan history)
- **Network**: High-speed internet for faster API responses

## 🔧 Step-by-Step Installation

### Step 1: Verify Python Installation

First, check if Python is installed on your system:

**Windows:**
```cmd
python --version
```
or
```cmd
python3 --version
```

**macOS/Linux:**
```bash
python3 --version
```

You should see output like `Python 3.9.7` or similar. If Python is not installed or the version is too old:

**Windows:**
1. Download Python from [python.org](https://python.org)
2. Run the installer and check "Add Python to PATH"
3. Restart your command prompt

**macOS:**
```bash
# Using Homebrew (recommended)
brew install python3

# Or download from python.org
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install python3 python3-pip
```

### Step 2: Download Project Files

You need all the project files in a single directory. Create a new folder and ensure you have:

```
network-security-platform/
├── app.py
├── requirements.txt
├── .env.example
├── pages/
│   ├── __init__.py
│   ├── auth.py
│   ├── home.py
│   ├── scan_file.py
│   └── scan_url.py
├── utils/
│   ├── auth_utils.py
│   ├── db_utils.py
│   └── virustotal_api.py
├── models/
├── static/
│   └── css/
└── data/ (will be created automatically)
```

### Step 3: Create Virtual Environment (Recommended)

A virtual environment keeps your project dependencies isolated:

**Windows:**
```cmd
cd network-security-platform
python -m venv venv
venv\Scripts\activate
```

**macOS/Linux:**
```bash
cd network-security-platform
python3 -m venv venv
source venv/bin/activate
```

You should see `(venv)` at the beginning of your command prompt, indicating the virtual environment is active.

### Step 4: Install Dependencies

With your virtual environment activated, install the required packages:

```bash
pip install -r requirements.txt
```

This will install:
- `streamlit` - Web framework
- `requests` - HTTP library for API calls
- `python-dotenv` - Environment variable management
- `bcrypt` - Password hashing

### Step 5: Configure Environment Variables

Create your environment configuration file:

**Windows:**
```cmd
copy .env.example .env
notepad .env
```

**macOS/Linux:**
```bash
cp .env.example .env
nano .env
```

Edit the `.env` file and add your VirusTotal API key:

```env
VIRUSTOTAL_API_KEY=your_actual_api_key_here
```

### Step 6: Get VirusTotal API Key

1. **Visit VirusTotal**: Go to [https://www.virustotal.com/](https://www.virustotal.com/)

2. **Create Account**: 
   - Click "Join our community"
   - Fill in your details and verify your email

3. **Get API Key**:
   - Log in to your account
   - Click on your username (top right)
   - Select "API Key" from the dropdown
   - Copy your API key

4. **Add to Configuration**:
   - Paste your API key in the `.env` file
   - Save the file

### Step 7: Test Installation

Test that everything is working:

```bash
# Make sure you're in the project directory and virtual environment is active
streamlit run app.py
```

You should see output like:
```
You can now view your Streamlit app in your browser.

Local URL: http://localhost:8501
Network URL: http://192.168.1.100:8501
```

### Step 8: Access the Application

1. **Open Browser**: Navigate to `http://localhost:8501`
2. **Create Account**: Go to "Login/Register" in the sidebar
3. **Register**: Fill in your details to create an account
4. **Login**: Sign in with your new credentials
5. **Start Using**: Begin scanning files and URLs!

## ✅ Verification Checklist

Make sure everything is working by checking:

- [ ] Python 3.7+ is installed and accessible
- [ ] Virtual environment is created and activated
- [ ] All dependencies are installed without errors
- [ ] `.env` file exists with valid VirusTotal API key
- [ ] Application starts without errors (`streamlit run app.py`)
- [ ] Can access web interface at `http://localhost:8501`
- [ ] Can create a user account
- [ ] Can navigate between different pages
- [ ] Database file is created in `data/app.db`

## 🚨 Common Issues and Solutions

### Issue 1: Python Not Found

**Problem**: `'python' is not recognized as an internal or external command`

**Solution**:
- **Windows**: Reinstall Python and check "Add Python to PATH"
- **macOS/Linux**: Use `python3` instead of `python`
- Restart your terminal/command prompt

### Issue 2: Permission Denied

**Problem**: Permission errors when installing packages

**Solution**:
```bash
# Use --user flag
pip install --user -r requirements.txt

# Or on Linux/macOS, use sudo (not recommended with virtual env)
sudo pip3 install -r requirements.txt
```

### Issue 3: Virtual Environment Issues

**Problem**: Virtual environment not activating

**Solution**:
```bash
# Delete and recreate virtual environment
rm -rf venv  # Linux/macOS
rmdir /s venv  # Windows

# Recreate
python -m venv venv
# Activate again
```

### Issue 4: Streamlit Not Found

**Problem**: `streamlit: command not found`

**Solution**:
```bash
# Make sure virtual environment is activated
# Reinstall streamlit
pip install streamlit

# Or run with python -m
python -m streamlit run app.py
```

### Issue 5: API Key Issues

**Problem**: "Invalid API key" or API errors

**Solution**:
1. Double-check your API key in the `.env` file
2. Ensure no extra spaces or characters
3. Verify your VirusTotal account is active
4. Test API key with curl:
   ```bash
   curl -H "X-Apikey: YOUR_API_KEY" https://www.virustotal.com/api/v3/files/limits
   ```

### Issue 6: Port Already in Use

**Problem**: "Port 8501 is already in use"

**Solution**:
```bash
# Use a different port
streamlit run app.py --server.port 8502

# Or kill existing Streamlit processes
# Windows:
taskkill /f /im streamlit.exe

# Linux/macOS:
pkill -f streamlit
```

### Issue 7: Database Errors

**Problem**: SQLite database errors

**Solution**:
```bash
# Create data directory manually
mkdir data

# Set proper permissions (Linux/macOS)
chmod 755 data

# Delete corrupted database
rm data/app.db
```

### Issue 8: Import Errors

**Problem**: `ModuleNotFoundError` for project modules

**Solution**:
- Ensure you're in the correct directory
- Check that all files are present
- Verify virtual environment is activated
- Reinstall dependencies

## 🔧 Advanced Configuration

### Custom Port Configuration

To run on a different port:

```bash
streamlit run app.py --server.port 8080
```

### Network Access

To allow access from other devices on your network:

```bash
streamlit run app.py --server.address 0.0.0.0
```

**Warning**: Only do this on trusted networks.

### Production Configuration

For production deployment:

```bash
streamlit run app.py --server.headless true --server.enableCORS false
```

## 🔒 Security Considerations

### Environment Variables
- Never commit `.env` files to version control
- Use strong, unique API keys
- Rotate API keys regularly

### Network Security
- Use HTTPS in production
- Configure firewall rules appropriately
- Monitor API usage and costs

### Data Privacy
- Files are sent to VirusTotal for analysis
- VirusTotal may retain files for research
- Don't upload confidential files

## 📊 Performance Optimization

### System Resources

Monitor resource usage:
- **CPU**: Streamlit is generally lightweight
- **Memory**: Increases with scan history
- **Network**: Depends on file sizes and API calls

### Database Maintenance

For better performance:
- Regularly clean old scan results
- Monitor database size
- Consider PostgreSQL for high volume

### API Optimization

- Monitor VirusTotal API quotas
- Implement caching for repeated requests
- Consider premium subscription for higher limits

## 🔄 Updates and Maintenance

### Regular Maintenance

1. **Update Dependencies**:
   ```bash
   pip install --upgrade -r requirements.txt
   ```

2. **Database Cleanup**:
   - Remove old scan results periodically
   - Backup important data

3. **Security Updates**:
   - Keep Python updated
   - Monitor for security advisories
   - Update API keys as needed

### Backup Procedures

```bash
# Backup database
cp data/app.db data/app.db.backup.$(date +%Y%m%d)

# Backup configuration
cp .env .env.backup
```

## 🆘 Getting Help

### Diagnostic Information

When seeking help, provide:

1. **System Information**:
   ```bash
   python --version
   pip list
   ```

2. **Error Messages**: Copy exact error text

3. **Configuration**: Check `.env` file (don't share API key)

4. **Logs**: Check terminal output for errors

### Log Files

Enable debug logging:
```bash
streamlit run app.py --logger.level debug
```

### Testing API Connection

Test your VirusTotal API key:
```bash
curl -H "X-Apikey: YOUR_API_KEY" https://www.virustotal.com/api/v3/files/limits
```

## 🎯 Next Steps

After successful setup:

1. **Create Admin Account**: First user becomes admin automatically
2. **Test File Scanning**: Upload a test file (like a text file)
3. **Test URL Scanning**: Scan a known safe URL (like google.com)
4. **Explore Dashboard**: Check your scan history and metrics
5. **Configure Preferences**: Adjust settings as needed

## 📱 Platform-Specific Notes

### Windows Specific
- Use Command Prompt or PowerShell
- Antivirus may flag Python scripts (add exception)
- Windows Defender may slow file operations

### macOS Specific
- May need to install Xcode command line tools
- Use Terminal application
- Homebrew recommended for Python installation

### Linux Specific
- Package manager varies by distribution
- May need to install additional development packages
- Check firewall settings for network access

## 🔍 Troubleshooting Checklist

If something isn't working:

1. [ ] Check Python version (`python --version`)
2. [ ] Verify virtual environment is activated
3. [ ] Confirm all dependencies are installed
4. [ ] Check `.env` file exists and has API key
5. [ ] Test API key with curl command
6. [ ] Verify internet connectivity
7. [ ] Check for error messages in terminal
8. [ ] Try restarting the application
9. [ ] Check file permissions on data directory
10. [ ] Verify all project files are present

---

**Need More Help?** 

If you're still having issues after following this guide:
1. Check the error messages carefully
2. Verify all steps were completed
3. Try the troubleshooting solutions above
4. Check the main README.md for additional information

**Success Indicators:**
- Application starts without errors
- Web interface loads at localhost:8501
- Can create and login to user account
- Can navigate between pages
- Database file appears in data/ directory

