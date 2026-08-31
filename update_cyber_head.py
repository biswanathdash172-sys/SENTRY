import re
with open('frontend/cyber-head-dashboard.html', 'r', encoding='utf-8') as f:
    html = f.read()

# 1. Update titles
html = html.replace('Admin ?" Risk & Scan Console', 'Cyber Head Portal')
html = html.replace('ADMIN CONSOLE', 'CYBER HEAD')

# 2. Add Email Intel and Whitelist before Auto-Approval Rules
email_and_whitelist = '''
      <!-- =================== EMAIL INTELLIGENCE =================== -->
      <div class="card" id="email-intel-card">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <h2>Live Email Intelligence</h2>
          <button class="btn small" onclick="openEmailModal()">See More</button>
        </div>
        <div id="email-banner" style="display:none;background:rgba(239,91,91,0.12);border:1px solid rgba(239,91,91,0.35);color:#ff8080;padding:12px 16px;border-radius:10px;margin-bottom:16px;font-size:0.85rem;"></div>
        <table>
          <thead>
            <tr>
              <th>From</th>
              <th>Subject</th>
              <th>Domain</th>
              <th>Risk Score</th>
              <th>Time</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="email-table-body">
            <tr><td colspan="6" class="empty">Loading email data...</td></tr>
          </tbody>
        </table>
      </div>

      <!-- =================== DOMAIN WHITELIST =================== -->
      <div class="card">
        <h2>Trusted Sender Domains (Whitelist)</h2>
        <div style="display:flex;gap:10px;align-items:flex-end;margin-bottom:16px;flex-wrap:wrap;">
          <div class="field" style="flex:1;min-width:200px;">
            <label for="new-domain">Add Trusted Domain</label>
            <input type="text" id="new-domain" placeholder="example.com" />
          </div>
          <button class="btn" onclick="addDomain()" style="white-space:nowrap;">Add Domain</button>
          <button class="btn secondary" onclick="autoAddDomains()" style="white-space:nowrap;" title="Auto-add safe domains from recent emails">Auto-Add Safe</button>
        </div>
        <div class="msg" id="whitelist-msg"></div>
        <div id="whitelist-list" style="display:flex;flex-direction:column;gap:8px;margin-top:8px;">
          <div class="empty">Loading...</div>
        </div>
      </div>
'''

html = re.sub(r'(<div class="card">\s*<h2>Auto-Approval Rules)', email_and_whitelist + r'\1', html)

# 3. Add Email Modal
email_modal = '''
    <!-- Email Modal -->
    <div id="email-modal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);z-index:100;align-items:center;justify-content:center;padding:20px;">
      <div class="card" style="width:100%;max-width:900px;max-height:80vh;display:flex;flex-direction:column;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <h2>Email Intelligence History</h2>
          <button class="btn small danger-outline" onclick="closeEmailModal()">Close</button>
        </div>
        <div style="overflow-y:auto;flex:1;">
          <table>
            <thead>
              <tr>
                <th>From</th>
                <th>Subject</th>
                <th>Domain</th>
                <th>Risk Score</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody id="email-modal-body">
            </tbody>
          </table>
        </div>
      </div>
    </div>
'''
html = html.replace('</main>', '</main>\n' + email_modal)

# 4. Remove Audit Log and Employee Management cards
html = re.sub(r'<!-- Audit log -->.*?<!-- Employee & role management -->', '<!-- Employee & role management -->', html, flags=re.DOTALL)
html = re.sub(r'<!-- Employee & role management -->.*?<script>', '<script>', html, flags=re.DOTALL)

with open('frontend/cyber-head-dashboard.html', 'w', encoding='utf-8') as f:
    f.write(html)
