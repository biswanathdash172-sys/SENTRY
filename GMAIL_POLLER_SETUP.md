# ✅ Gmail Poller - Complete Setup Guide for Cyberhead Portal

## 🎯 What We're Building
A service that **automatically monitors your Gmail inbox** and sends suspicious emails to the Cyberhead portal as alerts.

---

## 📋 Prerequisites Checklist

- [x] Gmail OAuth authorized (you completed this ✓)
- [ ] Backend `.env` file configured
- [ ] Cyberhead API running (`python main.py`)
- [ ] Employee account created in portal
- [ ] Gmail poller service running

---

## 🚀 Complete Step-by-Step Setup

### **Step 1: Check If Authorization is Complete**

Verify the `token.json` file exists:
```bash
cd C:\Users\LENOVO\OneDrive\Desktop\sentry-demo\backend
ls -la token.json
# Should show: token.json file created
```

If it exists, ✅ **Skip to Step 3**

---

### **Step 2: Complete Authorization (If Needed)**

```bash
cd C:\Users\LENOVO\OneDrive\Desktop\sentry-demo\backend
python services/gmail_poller.py --authorize
```

This will:
1. Open a browser to Google login
2. Ask for permissions
3. Create `token.json` (cached for future runs)

---

### **Step 3: Update `.env` File**

Open `.env` in the backend folder and configure:

```env
# Gmail configuration
IMAP_USER=your-email@gmail.com

# Cyberhead API connection
SENTRY_API_BASE=http://localhost:8000

# Employee credentials (create this account in the portal first!)
SENTRY_EMPLOYEE_USERNAME=your_username
SENTRY_EMPLOYEE_PASSWORD=your_password

# Poll interval (check emails every 30 seconds)
GMAIL_POLL_INTERVAL_SECONDS=30
```

⚠️ **IMPORTANT:** The `SENTRY_EMPLOYEE_USERNAME` and `SENTRY_EMPLOYEE_PASSWORD` must be an **existing employee account** in the Cyberhead portal!

---

### **Step 4: Create Employee Account in Portal**

1. **Start the Cyberhead backend:**
   ```bash
   cd C:\Users\LENOVO\OneDrive\Desktop\sentry-demo\backend
   python main.py
   ```
   Should show: `Uvicorn running on http://0.0.0.0:8000`

2. **Open the portal in browser:**
   ```
   http://localhost:3000  (or your frontend URL)
   ```

3. **Create an employee account:**
   - Login as admin
   - Go to Settings/Employees
   - Create new employee with:
     - Username: `your_username`
     - Password: `your_password`
   - Copy these exact values to `.env`

---

### **Step 5: Run the Gmail Poller**

**In a new terminal window:**
```bash
cd C:\Users\LENOVO\OneDrive\Desktop\sentry-demo\backend
python services/gmail_poller.py
```

You should see:
```
2026-09-02 01:30:00,000 [gmail-poller] Gmail API connected. Logging into Sentry as your_username...
2026-09-02 01:30:02,000 [gmail-poller] Got token. Starting Gmail poll loop...
2026-09-02 01:30:30,000 [gmail-poller] Scanned 'Test Email' from sender@example.com — score=0.2
```

---

### **Step 6: Send Test Emails to Trigger Alerts**

Send emails to your monitored Gmail address with **suspicious content**:

#### **Examples that will trigger alerts:**

1. **Phishing-like email:**
   ```
   Subject: Verify Your Account Immediately
   Body: Click here now to verify your PayPal account before it gets suspended!
   ```

2. **Urgency + Brand Mimicking:**
   ```
   Subject: Apple Security Alert
   Body: Your password expires immediately. Wire transfer required.
   ```

3. **Suspicious URL:**
   ```
   Subject: Download invoice
   Body: Click here: http://suspicious-domain.zip/invoice
   ```

---

### **Step 7: Check Portal for Alerts**

1. **Open Cyberhead Portal:** `http://localhost:3000`
2. **Navigate to:** Inbox or Email Evidence section
3. **You should see:**
   - Detected emails listed
   - Risk score shown
   - Suspicious reasons explained

---

## 🔧 Troubleshooting

### **Issue: "Missing required env vars"**
**Solution:** Make sure these are in `.env`:
```env
SENTRY_EMPLOYEE_USERNAME=xxx
SENTRY_EMPLOYEE_PASSWORD=xxx
```

### **Issue: "Gmail API not available"**
**Solution:** Check `token.json` exists:
```bash
ls -la backend/token.json
```
If missing, re-run: `python services/gmail_poller.py --authorize`

### **Issue: "Ingest failed (401)"**
**Solution:** Your employee credentials are wrong
- Delete the current employee from portal
- Create a new one with correct username/password
- Update `.env` and restart poller

### **Issue: "No emails fetched"**
**Solution:** Wait 30 seconds for next poll, or send a test email

---

## 📊 Data Flow Diagram

```
┌─────────────┐
│   Gmail     │
│  Inbox      │
└──────┬──────┘
       │ (every 30 seconds)
       │
┌──────v────────────────────┐
│ gmail_poller.py            │
│ - Fetches emails           │
│ - Scores suspicious emails │
│ - Creates alerts           │
└──────┬────────────────────┘
       │ (POST /ingest/email)
       │
┌──────v────────────────────┐
│ Cyberhead API              │
│ - Correlates evidence      │
│ - Runs playbooks           │
│ - Updates portal           │
└──────┬────────────────────┘
       │
┌──────v────────────────────┐
│ Portal (React Frontend)    │
│ - Shows detected emails    │
│ - Displays risk scores     │
│ - Lists suspicious reasons │
└────────────────────────────┘
```

---

## ✅ Verification Checklist

- [ ] `token.json` exists in backend folder
- [ ] `.env` has `SENTRY_EMPLOYEE_USERNAME` and `SENTRY_EMPLOYEE_PASSWORD`
- [ ] Employee account created in portal with same credentials
- [ ] Backend API running (`python main.py`)
- [ ] Gmail poller running (`python services/gmail_poller.py`)
- [ ] Test email sent to your Gmail address
- [ ] Alert visible in portal inbox

---

## 🚀 Quick Start (All at Once)

**Terminal 1 - Start Backend API:**
```bash
cd backend
python main.py
```

**Terminal 2 - Start Gmail Poller:**
```bash
cd backend
python services/gmail_poller.py
```

**Terminal 3 - View Logs:**
```bash
# Already running, just watch Terminal 2 for:
# "[gmail-poller] Got token. Starting Gmail poll loop..."
```

**Browser - Check Portal:**
```
http://localhost:3000
→ Login → Go to Inbox/Email Evidence
→ See detected emails!
```

---

## 📞 Need Help?

If something doesn't work:
1. Check `.env` file - most issues are config related
2. Check logs in Terminal 2 for errors
3. Verify backend is running on `http://localhost:8000`
4. Verify employee account exists in portal
5. Send test email to your Gmail address

---

**You're all set! 🎉**
