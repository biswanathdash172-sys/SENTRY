import re
with open('frontend/org-dashboard.html', 'r', encoding='utf-8') as f:
    html = f.read()

new_js = '''
      let fullAuditLogs = [];
      function openAuditModal() {
        document.getElementById('audit-modal').style.display = 'flex';
        const tbody = document.getElementById('audit-modal-body');
        tbody.innerHTML = fullAuditLogs.map(l => {
          const time = l.created_at ? new Date(l.created_at).toLocaleString() : '-';
          return \<tr>
            <td style="font-size:0.75rem;color:var(--muted);">\</td>
            <td class="mono" style="font-size:0.75rem;">\</td>
            <td style="font-size:0.8rem;">\</td>
          </tr>\;
        }).join("");
      }
      function closeAuditModal() {
        document.getElementById('audit-modal').style.display = 'none';
      }
      async function loadAuditLog() {
        try {
          const res = await fetch("/audit-log", { headers: authHeaders() });
          if (await handle401(res)) return;
          if (!res.ok) return;
          fullAuditLogs = await res.json();
          const tbody = document.getElementById("audit-table-body");
          if (!fullAuditLogs.length) {
            tbody.innerHTML = \<tr><td colspan="3" class="empty">No audit entries recorded yet.</td></tr>\;
            return;
          }
          tbody.innerHTML = fullAuditLogs.slice(0, 5).map(l => {
            const time = l.created_at ? new Date(l.created_at).toLocaleString() : '-';
            return \<tr>
              <td style="font-size:0.75rem;color:var(--muted);">\</td>
              <td class="mono" style="font-size:0.75rem;">\</td>
              <td style="font-size:0.8rem;">\</td>
            </tr>\;
          }).join("");
        } catch (e) {
          console.error("Audit log load error:", e);
        }
      }
'''

html = re.sub(r'async function loadAuditLog\(\) \{.*?\} catch \(e\) \{\n.*?\console\.error.*?\n.*?\}\n\s*\}', new_js, html, flags=re.DOTALL)

with open('frontend/org-dashboard.html', 'w', encoding='utf-8') as f:
    f.write(html)
