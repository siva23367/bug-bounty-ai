import React, { useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import './style.css';

const modules = {
  reflection: 'HTML reflection', sqli: 'SQL error indicators', redirect: 'Open redirects', cors: 'CORS origin test',
  exposure: 'Configuration exposure', access: 'Test-account access', stored: 'Stored inert marker', ssrf: 'Controlled callback',
};
const colors = { Critical: '#fb7185', High: '#fb923c', Medium: '#facc15', Low: '#5eead4', Info: '#64748b' };
const lines = value => value.split('\n').map(s => s.trim()).filter(Boolean);
const money = (cents, currency) => `${currency} ${(cents / 100).toLocaleString(undefined, { minimumFractionDigits: 2 })}`;
const badge = value => <span className={`badge ${value}`}>{value.replaceAll('_', ' ')}</span>;
const isServerUnavailable = error => error instanceof TypeError ||
  /Failed to fetch|NetworkError|connection refused|not running|cannot reach/i.test(error.message || String(error));

function App() {
  const [token, setToken] = useState('');
  const [keyInput, setKeyInput] = useState('');
  const [page, setPage] = useState('Overview');
  const [programs, setPrograms] = useState([]);
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState(null);
  const [settings, setSettings] = useState(null);
  const [scan, setScan] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState(null);
  const [serverOffline, setServerOffline] = useState(false);

  const api = useCallback(async (path, options = {}) => {
    let response;
    try {
      response = await fetch('/api' + path, { ...options, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...options.headers } });
    } catch (fetchError) {
      throw new Error('Cannot reach the local server. Start Bug Bounty AI on http://127.0.0.1:8000, then retry.');
    }
    if (!response.ok) {
      const data = await response.json().catch(() => ({ detail: `Request failed (${response.status})` }));
      throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail));
    }
    return options.download ? response.blob() : response.json();
  }, [token]);

  const refresh = useCallback(async () => {
    const [p, s, d, c] = await Promise.all([api('/programs'), api('/scans'), api('/dashboard'), api('/settings')]);
    setPrograms(p); setScans(s); setStats(d); setSettings(c);
  }, [api]);

  const act = async action => {
    setBusy(true); setError(''); setNotice('');
    try { await action(); setServerOffline(false); return true; } catch (e) {
      if (isServerUnavailable(e)) setServerOffline(true);
      else setError(e.message);
      return false;
    } finally { setBusy(false); }
  };

  useEffect(() => {
    if (!token) return;
    let live = true;
    const update = async () => {
      try {
        await refresh();
        if (live) setServerOffline(false);
        if (scan?.id) {
          const data = await api(`/scans/${scan.id}`);
          if (live) setScan(data);
        }
      } catch (e) {
        if (!live) return;
        if (isServerUnavailable(e)) {
          setServerOffline(true);
          setError('');
        } else setError(e.message);
      }
    };
    update();
    const timer = setInterval(update, 4000);
    return () => { live = false; clearInterval(timer); };
  }, [token, refresh, api, scan?.id]);

  async function openScan(id) {
    setScan(await api(`/scans/${id}`)); setPage('Investigations'); setSelected(null);
  }
  async function download(id, format) {
    const blob = await api(`/findings/${id}/report/${format}`, { download: true });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = url; link.download = `finding-${id}.${format}`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setNotice(`Downloaded ${format.toUpperCase()} report.`);
  }

  if (!token) return <main className="login">
    <div className="login-card"><div className="logo-mark">B/</div><p className="eyebrow">AUTHORIZED RESEARCH ONLY</p>
      <h1>Bug Bounty <em>AI</em></h1><p className="muted mt-4">A local workspace for evidence-led security research.<br />Your targets. Your permission. Your control.</p>
      <form onSubmit={e => { e.preventDefault(); setError(''); setToken(keyInput.trim()); setKeyInput(''); }}>
        <label className="mt-8">Local API token<input autoComplete="off" type="password" required value={keyInput} onChange={e => setKeyInput(e.target.value)} placeholder="Paste your local access token" /></label>
        <p className="hint">Read data/api-token on the server, or use your configured API_TOKEN. The key stays in browser memory only.</p>
        <button className="primary w-full mt-5">Open research workspace <span>→</span></button>
      </form>
      <p className="hint mt-6">No arbitrary scanning. Every request must match approved, unexpired scope.</p>
    </div>
  </main>;

  return <div className="shell">
    <aside><div className="brand"><span className="logo-mark">B/</span><div>Bug Bounty <b>AI</b><small>RESEARCH WORKSPACE</small></div></div>
      <div className="nav-label">WORKSPACE</div><nav>{['Overview', 'New scan', 'Investigations', 'Programs', 'Intelligence'].map((name, i) =>
        <button key={name} className={page === name ? 'active' : ''} onClick={() => { setPage(name); setError(''); }}><span className="nav-number">0{i + 1}</span>{name}</button>)}</nav>
      <div className="sidebar-bottom"><span className="dot" /> LOCAL / SINGLE USER<p>Evidence, not assumptions.<br />No guaranteed bounties.</p>
        <button className="text-button" onClick={() => { setToken(''); setScan(null); setSelected(null); setStats(null); }}>Lock workspace</button></div>
    </aside>
    <div className="workspace"><header><span>Workspace <span className="muted">/</span> {page}</span><span className="environment"><span className="dot" /> {settings?.loopback_enabled ? 'LOCAL LAB ENABLED' : 'SCOPE ENFORCED'}</span></header>
      <main className="content"><div className="page-title"><div><p className="eyebrow">SECURITY RESEARCH / CONTROL CENTER</p><h1>{page === 'Overview' ? 'Research overview' : page}</h1></div>
        {page === 'Overview' && <button className="primary" onClick={() => setPage('New scan')}>+ New authorized scan</button>}</div>
        {serverOffline && <div className="alert offline" role="alert">
          <div><b>Local server unavailable</b><span>Waiting for http://127.0.0.1:8000 to respond. The workspace reconnects automatically.</span></div>
          <button onClick={() => act(async () => { await refresh(); setNotice('Local server connection restored.'); })}>Retry connection</button>
        </div>}
        {error && <div className="alert error" role="alert">{error}<button onClick={() => setError('')}>Dismiss</button></div>}
        {notice && <div className="alert" role="status">{notice}<button onClick={() => setNotice('')}>Dismiss</button></div>}

        {page === 'Overview' && stats && <>
          <div className="safety-strip"><span className="dot" /><b>Permission first. Evidence always.</b><span>Indicators require human validation before submission.</span></div>
          <div className="metrics">{[['Total scans', stats.scans, 'Persisted research sessions'], ['Findings observed', stats.findings, 'Not necessarily vulnerabilities'], ['Confirmed', stats.confirmed, 'Human-reviewed evidence'], ['Potential', stats.potential, 'Awaiting investigation']].map(([title, value, hint]) =>
            <section className="metric" key={title}><div>{title}</div><strong>{value.toString().padStart(2, '0')}</strong><small>{hint}</small></section>)}</div>
          <div className="two-column"><section className="panel"><div className="panel-heading"><h2>Severity distribution</h2><span className="muted text-xs">FALSE POSITIVES EXCLUDED</span></div>
            <div className="chart"><ResponsiveContainer width="100%" height={210}><BarChart data={Object.entries(stats.severities).map(([name, count]) => ({ name, count }))}>
              <XAxis dataKey="name" stroke="#8694a8" tickLine={false} axisLine={false} fontSize={12} /><YAxis allowDecimals={false} stroke="#8694a8" tickLine={false} axisLine={false} fontSize={12} width={25} />
              <Tooltip contentStyle={{ background: '#151e2a', border: '1px solid #334155', borderRadius: 8, color: '#fff' }} cursor={{ fill: '#ffffff05' }} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={42}>{Object.keys(stats.severities).map(name => <Cell key={name} fill={colors[name]} />)}</Bar>
            </BarChart></ResponsiveContainer></div>
          </section><section className="panel"><div className="panel-heading"><h2>Disclosure & rewards</h2><span className="badge">OPERATOR RECORDED</span></div>
            <div className="submission-grid">{Object.entries(stats.submissions).map(([name, count]) => <div key={name}><strong>{count}</strong><span>{name}</span></div>)}</div>
            <div className="reward-row"><span>Actual earnings / Pending</span><b>{Object.keys(stats.rewards).length ? Object.entries(stats.rewards).map(([currency, values]) => <div key={currency}>{money(values.earned_cents, currency)} / {money(values.pending_cents, currency)}</div>) : 'No rewards recorded'}</b></div>
            <p className="hint">{stats.false_positive} false positives reviewed. Rewards are never estimated from findings.</p>
          </section></div>
          <ScanList scans={scans} onOpen={id => act(() => openScan(id))} onNew={() => setPage('New scan')} />
        </>}
        {page === 'New scan' && <ScanForm programs={programs} busy={busy} onPrograms={() => setPage('Programs')} onStart={values => act(async () => { const result = await api('/scans', { method: 'POST', body: JSON.stringify(values) }); await openScan(result.id); await refresh(); })} />}
        {page === 'Programs' && <Programs programs={programs} busy={busy} onSave={values => act(async () => { await api('/programs', { method: 'POST', body: JSON.stringify(values) }); await refresh(); setNotice('Authorization saved. Credentials encrypted at rest.'); })} onRevoke={id => act(async () => { await api(`/programs/${id}/revoke`, { method: 'POST' }); await refresh(); setNotice('Authorization revoked and associated scans stopped.'); })} />}
        {page === 'Intelligence' && <Intelligence api={api} act={act} programs={programs} settings={settings} busy={busy} />}
        {page === 'Investigations' && <>
          <ScanList scans={scans} onOpen={id => act(() => openScan(id))} onNew={() => setPage('New scan')} />
          {scan && <section className="panel mt-6"><div className="panel-heading"><div><h2>Scan #{scan.id} {badge(scan.status)}</h2><p className="mono muted break-all mt-2">{scan.target}</p></div>
            {['running', 'queued'].includes(scan.status) && <button className="danger" disabled={busy} onClick={() => act(async () => { await api(`/scans/${scan.id}/stop`, { method: 'POST' }); await openScan(scan.id); })}>STOP SCAN</button>}</div>
            <p className="hint">{scan.request_count} requests attempted. Findings are potential until reviewed. {scan.error}</p>
            {['confirmed', 'potential', 'false_positive'].map(status => <div key={status} className="finding-group"><h3>{status.replaceAll('_', ' ')} <span>{scan.findings.filter(f => f.status === status).length}</span></h3>
              {scan.findings.filter(f => f.status === status).map(f => <button className="finding" key={f.id} onClick={() => setSelected(f)}><span className="severity" style={{ color: colors[f.severity] }}>{f.severity}</span><span><b>{f.title}</b><small>{f.endpoint}</small></span><span className="muted">Investigate →</span></button>)}
              {!scan.findings.some(f => f.status === status) && <p className="hint">No {status.replaceAll('_', ' ')} findings.</p>}</div>)}
            <details className="mt-6"><summary>Reconnaissance inventory & excluded URLs</summary><pre>{JSON.stringify(scan.inventory, null, 2)}</pre></details>
            <details className="mt-4"><summary>Complete scan audit log ({scan.logs.length} events)</summary><div className="logs">{scan.logs.map(log => <div key={log.id}><time>{log.created_at}</time><b>{log.event}</b><pre>{JSON.stringify(log.details)}</pre></div>)}</div></details>
          </section>}
        </>}
        <footer>BUG BOUNTY AI <span>Scope-bound testing / Redacted evidence / Human verification</span></footer>
      </main>
    </div>
    {selected && <FindingDetail finding={selected} busy={busy} error={error} notice={notice} aiLocal={settings?.llm_local} aiAvailable={settings?.llm_configured} onClose={() => setSelected(null)} onDownload={format => act(() => download(selected.id, format))}
      onReview={body => act(async () => { await api(`/findings/${selected.id}/review`, { method: 'PATCH', body: JSON.stringify(body) }); setSelected({ ...selected, status: body.status, severity: body.severity, cvss: body.cvss, review_note: body.note }); await refresh(); setScan(await api(`/scans/${scan.id}`)); setNotice('Human review saved.'); })}
      onSubmission={body => act(async () => { await api(`/findings/${selected.id}/submission`, { method: 'PATCH', body: JSON.stringify(body) }); setSelected({ ...selected, submission: body.status }); await refresh(); setNotice('Submission outcome recorded. No report was transmitted.'); })}
      onAI={() => act(async () => { const result = await api(`/findings/${selected.id}/analyze`, { method: 'POST' }); setSelected({ ...selected, ai_analysis: result }); })} />}
  </div>;
}

function ScanList({ scans, onOpen, onNew }) {
  return <section className="panel"><div className="panel-heading"><h2>Scan activity</h2><span className="muted text-xs">MOST RECENT 200</span></div>
    {!scans.length ? <div className="empty"><div className="empty-icon">[ / ]</div><h3>Your research starts here</h3><p>Add documented permission, define the scope, then start a scan.</p><button onClick={onNew}>Create your first scan →</button></div> :
      <div className="table-scroll"><table><thead><tr><th>Target</th><th>Status</th><th>Requests</th><th>Started</th><th /></tr></thead><tbody>{scans.map(s => <tr key={s.id}><td><span className="mono">#{s.id}</span> {s.target}</td><td>{badge(s.status)}</td><td>{s.request_count}</td><td>{new Date(s.created_at).toLocaleString()}</td><td><button className="text-button" onClick={() => onOpen(s.id)}>Open →</button></td></tr>)}</tbody></table></div>}
  </section>;
}

function ScanForm({ programs, busy, onPrograms, onStart }) {
  const [programId, setProgramId] = useState('');
  const [active, setActive] = useState([]);
  const program = programs.find(p => p.id === Number(programId));
  const valid = programs.filter(p => !p.revoked && new Date(p.policy.expires_at) > new Date());
  return <form className="panel max-w-4xl" onSubmit={e => { e.preventDefault(); const f = new FormData(e.currentTarget); onStart({ program_id: Number(programId), target: f.get('target'), active_modules: active, active_approved: f.get('approved') === 'on', approval_note: f.get('note') || '' }); }}>
    <div className="panel-heading"><h2>Define a bounded scan</h2><span className="badge">AUTHORIZATION REQUIRED</span></div>
    {!valid.length && <div className="alert">No active authorizations. <button type="button" onClick={onPrograms}>Add a program first →</button></div>}
    <label>Approved authorization<select required value={programId} onChange={e => { setProgramId(e.target.value); setActive([]); }}><option value="">Select a program</option>{valid.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
    <label>Target URL<input name="target" type="url" required placeholder="https://authorized.example.com/" /></label>
    {program && <div className="policy-box"><b>{program.policy.max_requests} requests maximum / {program.policy.requests_per_second} requests per second / {program.policy.max_pages} pages</b><p>Expires {new Date(program.policy.expires_at).toLocaleString()}</p><details><summary>Read approved rules & scope</summary><pre>{JSON.stringify(program.policy, null, 2)}</pre></details></div>}
    <h3 className="mt-6">Active tests <span className="muted text-sm">Optional, individually approved</span></h3>
    <div className="checkbox-grid">{Object.entries(modules).map(([key, title]) => <label className="check" key={key}><input type="checkbox" checked={active.includes(key)} disabled={!program?.policy.allowed_active.includes(key)} onChange={e => setActive(e.target.checked ? [...active, key] : active.filter(k => k !== key))} />{title}</label>)}</div>
    <p className="hint">Baseline mode still makes scoped GET requests. It does not mean zero traffic. No active test runs without both policy permission and approval here.</p>
    {active.length > 0 && <div className="policy-box"><label>Per-scan approval & constraints<textarea name="note" required minLength={20} placeholder="Why these exact tests are authorized, including dedicated resource and cleanup requirements..." /></label><label className="check"><input name="approved" type="checkbox" required />I approve these active tests. Stored-marker tests write disposable data and require manual cleanup.</label></div>}
    <button disabled={busy || !program} className="primary mt-6">{busy ? 'Starting...' : 'START SCAN'} →</button>
  </form>;
}

function Programs({ programs, busy, onSave, onRevoke }) {
  const [active, setActive] = useState([]);
  const [formError, setFormError] = useState('');
  return <div className="two-column align-start"><section className="panel"><div className="panel-heading"><h2>Authorization registry</h2><span className="badge">{programs.length} RECORDS</span></div>
    <p className="hint">Records are immutable. Revoke and create a new authorization when scope or rules change. A public program listing alone does not authorize scanning.</p>
    {programs.map(p => <article className="program-card" key={p.id}><div className="flex justify-between gap-3"><h3>{p.name}</h3>{badge(p.revoked ? 'revoked' : new Date(p.policy.expires_at) < new Date() ? 'expired' : 'approved')}</div><p className="mono mt-3">{p.policy.scope.map(s => s.origin + s.path_prefix).join('\n')}</p>
      <a href={p.policy.source_url} target="_blank" rel="noreferrer">Review permission source ↗</a><details className="mt-3"><summary>Rules & test configuration counts</summary><pre>{JSON.stringify(p.policy, null, 2)}</pre></details>
      {!p.revoked && <button className="danger mt-4" disabled={busy} onClick={() => onRevoke(p.id)}>Revoke authorization</button>}</article>)}
    {!programs.length && <p className="empty">No authorizations yet. Add your own test environment or a program with explicit automation permission.</p>}
  </section><form className="panel" onSubmit={async e => {
    e.preventDefault(); setFormError(''); const form = e.currentTarget; const f = new FormData(form);
    try {
      const advanced = JSON.parse(f.get('advanced') || '{}');
      const permitted = ['accounts', 'access_cases', 'stored_cases', 'ssrf_cases'];
      if (Object.keys(advanced).some(k => !permitted.includes(k))) throw new Error('Advanced JSON accepts only accounts, access_cases, stored_cases, ssrf_cases.');
      const values = { ...advanced, name: f.get('name'), source_url: f.get('source'), permission_reference: f.get('permission'), rules_text: f.get('rules'),
        scope: lines(f.get('scope')).map(line => { const [origin, path_prefix = '/'] = line.split(/\s+/); return { origin, path_prefix }; }),
        excluded_urls: lines(f.get('excluded')), excluded_categories: lines(f.get('excluded_categories')),
        expires_at: new Date(f.get('expires')).toISOString(), requests_per_second: Number(f.get('rps')), max_requests: Number(f.get('budget')), max_pages: Number(f.get('pages')),
        allowed_active: active, passive_subdomains_allowed: f.get('ct') === 'on', permission_attested: true, automation_allowed: true, rules_reviewed: true };
      if (await onSave(values)) { form.reset(); setActive([]); }
    } catch (error) { setFormError(error.message); }
  }}><h2>Add documented permission</h2><p className="hint">Scope and prose rules require human review. This application cannot establish legal permission or automatically interpret every program rule.</p>
    {formError && <div className="alert error">{formError}</div>}
    <label>Program / authorization name<input name="name" required minLength={2} /></label>
    <label>Official program or permission-document URL<input name="source" type="url" required placeholder="https://..." /></label>
    <label>Permission reference<textarea name="permission" required minLength={20} placeholder="Who authorized testing, when, and where the written permission is recorded." /></label>
    <label>Testing rules<textarea name="rules" required minLength={20} placeholder="Paste the current program rules. Translate all limits and exclusions into the fields below." /></label>
    <label>Approved origins and optional path prefixes (one per line)<textarea name="scope" required placeholder={'https://example.com /app\nhttps://*.example.com /'} className="mono" /></label>
    <label>Excluded URL globs (one per line)<textarea name="excluded" placeholder={'https://example.com/admin*\nhttps://example.com/logout*'} className="mono" /></label>
    <label>Non-eligible categories (one per line)<textarea name="excluded_categories" placeholder={'headers\ncookies'} className="mono" /></label>
    <div className="grid grid-cols-3 gap-3"><label>Requests/sec<input name="rps" type="number" min="0.1" max="5" step="0.1" defaultValue="1" required /></label><label>Request budget<input name="budget" type="number" min="1" max="500" defaultValue="50" required /></label><label>Page budget<input name="pages" type="number" min="1" max="100" defaultValue="15" required /></label></div>
    <label>Permission expiry (your local timezone)<input name="expires" type="datetime-local" required /></label>
    <h3 className="mt-5">Program-permitted active tests</h3><div className="checkbox-grid">{Object.entries(modules).map(([key, title]) => <label key={key} className="check"><input type="checkbox" checked={active.includes(key)} onChange={e => setActive(e.target.checked ? [...active, key] : active.filter(k => k !== key))} />{title}</label>)}</div>
    <details className="mt-5"><summary>Dedicated test accounts & controlled test cases</summary><p className="hint">Encrypted at rest. Credentials are never sent outside their exact origin. See README for the complete configuration schema. Do not use real user accounts.</p><label>Advanced configuration JSON<textarea name="advanced" className="mono min-h-48" autoComplete="off" placeholder={'{"accounts": [], "access_cases": [], "stored_cases": [], "ssrf_cases": []}'} /></label></details>
    <label className="check mt-5"><input type="checkbox" name="ct" />Permit passive crt.sh lookups (sends the approved public base domain)</label>
    <label className="check"><input type="checkbox" required />I have written permission, reviewed the current rules and scope, and verified that automated testing is allowed. The limits above enforce those rules.</label>
    <button className="primary mt-5" disabled={busy}>Save authorization</button>
  </form></div>;
}

function Intelligence({ api, act, programs, settings, busy }) {
  const [result, setResult] = useState(null);
  return <><div className="two-column align-start"><form className="panel" onSubmit={e => { e.preventDefault(); const f = new FormData(e.currentTarget); act(async () => setResult(await api(`/integrations/${f.get('provider')}/${encodeURIComponent(f.get('identifier'))}`))); }}>
    <h2>Official program lookup</h2><p className="hint">Read-only provider APIs. No scope is automatically trusted or imported. Review returned policy, all pagination links, eligible assets and published reward fields before creating authorization.</p>
    <label>Platform<select name="provider">{['hackerone', 'bugcrowd', 'intigriti'].map(p => <option key={p} value={p}>{p} {settings?.providers[p] ? '(configured)' : '(credentials required)'}</option>)}</select></label>
    <label>Program handle / ID<input name="identifier" required pattern="[a-zA-Z0-9_-]+" /></label><button className="primary mt-4" disabled={busy}>Retrieve published program data</button>
    <p className="hint mt-4">Missing reward fields mean unknown, never zero or guaranteed. security.txt policy links discovered in scans are candidates, not proof of official ownership.</p>
  </form><form className="panel" onSubmit={e => { e.preventDefault(); const f = new FormData(e.currentTarget); act(async () => setResult(await api(`/programs/${f.get('program')}/subdomains?domain=${encodeURIComponent(f.get('domain'))}`))); }}>
    <h2>Passive subdomain discovery</h2><p className="hint">Certificate Transparency records from crt.sh. Requires explicit permission. Discovery never expands scan scope or starts requests to discovered hosts.</p>
    <label>Approved program<select name="program" required><option value="">Select authorization</option>{programs.filter(p => !p.revoked && p.policy.passive_subdomains_allowed).map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
    <label>Approved public base domain<input name="domain" required placeholder="example.com" /></label><button className="primary mt-4" disabled={busy}>Query permitted passive source</button>
  </form></div>{result && <section className="panel mt-6"><h2>Source response</h2><p className="hint">{result.notice}</p><pre>{JSON.stringify(result, null, 2)}</pre></section>}</>;
}

function FindingDetail({ finding: f, busy, error, notice, aiLocal, aiAvailable, onClose, onDownload, onReview, onSubmission, onAI }) {
  return <div className="modal-backdrop"><section className="modal" role="dialog" aria-modal="true" aria-label="Finding investigation"><div className="panel-heading"><div><p className="eyebrow">FINDING #{f.id} / {f.category}</p><h2>{f.title}</h2></div><button onClick={onClose} aria-label="Close investigation">Close</button></div>
    {error && <div className="alert error" role="alert">{error}</div>}{notice && <div className="alert" role="status">{notice}</div>}
    <div className="flex gap-3 mb-4">{badge(f.status)}<span style={{ color: colors[f.severity] }}>{f.severity}</span></div><p className="mono break-all">{f.endpoint}</p><div className="policy-box">{f.eligibility}</div>
    {[['Description', f.description], ['Potential impact', f.impact], ['Remediation', f.remediation]].map(([title, text]) => <div key={title} className="mt-5"><h3>{title}</h3><p className="muted mt-2">{text}</p></div>)}
    <h3 className="mt-5">Safe reproduction</h3><ol className="list-decimal ml-5 muted">{f.steps.map((step, i) => <li key={i}>{step}</li>)}</ol><h3 className="mt-5">Evidence (sensitive values redacted)</h3><pre>{JSON.stringify(f.evidence, null, 2)}</pre>
    <div className="flex flex-wrap gap-3 mt-5">{['md', 'html', 'pdf'].map(format => <button key={format} disabled={busy} onClick={() => onDownload(format)}>Export {format.toUpperCase()}</button>)}<button disabled={busy || !aiAvailable} onClick={onAI}>Analyze with AI</button></div>
    <p className="hint">{aiAvailable ? (aiLocal ? 'Your loopback model receives redacted evidence for advisory analysis. AI cannot confirm a finding.' : 'Only generic detector metadata is sent to your configured model. AI cannot confirm a finding.') : 'AI unavailable: configure an OpenAI-compatible model endpoint in .env.'}</p>
    {f.ai_analysis && <pre>{JSON.stringify(f.ai_analysis, null, 2)}</pre>}
    <form className="divider" onSubmit={e => { e.preventDefault(); const data = new FormData(e.currentTarget); onReview({ status: data.get('status'), severity: data.get('severity'), note: data.get('note'), cvss: data.get('cvss') || null }); }}>
      <h3>Human verification</h3><div className="grid grid-cols-3 gap-3"><label>Disposition<select name="status" defaultValue={f.status}><option value="potential">Potential</option><option value="confirmed">Confirmed</option><option value="false_positive">False positive</option></select></label><label>Severity<select name="severity" defaultValue={f.severity}>{Object.keys(colors).map(s => <option key={s}>{s}</option>)}</select></label><label>CVSS (optional)<input name="cvss" type="number" min="0" max="10" step="0.1" defaultValue={f.cvss || ''} /></label></div>
      <label>Validation evidence and reasoning<textarea name="note" required minLength={20} defaultValue={f.review_note} placeholder="Document authorization, observed behavior, impact, and false-positive checks..." /></label><button className="primary mt-4" disabled={busy}>Save human review</button>
    </form>
    <form className="divider" onSubmit={e => { e.preventDefault(); const data = new FormData(e.currentTarget); onSubmission({ status: data.get('status'), url: data.get('url'), currency: data.get('currency'), earned_cents: Math.round(Number(data.get('earned')) * 100), pending_cents: Math.round(Number(data.get('pending')) * 100) }); }}>
      <h3>Record a submission outcome</h3><p className="hint">Export and submit manually to the authorized program. This form records actual outcomes; it does not transmit reports or create earnings.</p>
      <label>Status<select name="status" defaultValue={f.submission}>{['draft', 'submitted', 'accepted', 'rejected', 'duplicate'].map(s => <option key={s}>{s}</option>)}</select></label><label>Submission reference URL<input name="url" type="url" defaultValue={f.submission_url} placeholder="https://..." /></label>
      <div className="grid grid-cols-3 gap-3"><label>Currency<input name="currency" pattern="[A-Z]{3}" defaultValue={f.reward_currency} required /></label><label>Actually paid<input name="earned" type="number" min="0" step="0.01" defaultValue={f.earned_cents / 100} required /></label><label>Pending award<input name="pending" type="number" min="0" step="0.01" defaultValue={f.pending_cents / 100} required /></label></div><button className="mt-4" disabled={busy}>Save recorded outcome</button>
    </form>
  </section></div>;
}

createRoot(document.getElementById('root')).render(<App />);
