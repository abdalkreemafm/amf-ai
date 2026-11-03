import { useCallback, useEffect, useMemo, useState } from 'react';
import { createJob, getHealth, getJob, getModules, getProfiles, lookupNvd } from './services/api';
import type { Finding, Job, ModuleInfo, NVDLookupResponse, ProfileInfo, RunResult, Severity } from './types/amf';

const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export default function App() {
  const [modules, setModules] = useState<ModuleInfo[]>([]);
  const [profiles, setProfiles] = useState<ProfileInfo[]>([]);
  const [target, setTarget] = useState('');
  const [allow, setAllow] = useState('');
  const [profile, setProfile] = useState('web');
  const [execute, setExecute] = useState(false);
  const [results, setResults] = useState<RunResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingInitial, setLoadingInitial] = useState(true);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState('');
  const [job, setJob] = useState<Job | null>(null);
  const [nvdQuery, setNvdQuery] = useState('');
  const [nvdLoading, setNvdLoading] = useState(false);
  const [nvdError, setNvdError] = useState('');
  const [nvdData, setNvdData] = useState<NVDLookupResponse | null>(null);

  const loadDashboard = useCallback(async () => {
    setLoadingInitial(true);
    setError('');
    try {
      const [moduleData, profileData] = await Promise.all([getModules(), getProfiles(), getHealth()]);
      setModules(moduleData.modules);
      setProfiles(profileData.profiles);
      setConnected(true);
    } catch (reason) {
      setConnected(false);
      setError(reason instanceof Error ? reason.message : 'تعذر تحميل لوحة التحكم');
    } finally {
      setLoadingInitial(false);
    }
  }, []);

  useEffect(() => { void loadDashboard(); }, [loadDashboard]);

  const findings = useMemo(() => results.flatMap((result) => result.findings), [results]);
  const counts = useMemo(() => severityOrder.reduce<Record<string, number>>((acc, level) => {
    acc[level] = findings.filter((finding) => finding.severity === level).length;
    return acc;
  }, {}), [findings]);

  async function startScan() {
    setError('');
    setResults([]);
    setLoading(true);
    try {
      let current = (await createJob({ target, allow: [allow], execute, confirm_authorized_use: execute, profile, timeout: 5 })).job;
      setJob(current);
      while (current.status === 'queued' || current.status === 'running') {
        await new Promise((resolve) => window.setTimeout(resolve, 250));
        current = (await getJob(current.id)).job;
        setJob(current);
      }
      if (current.status === 'failed') throw new Error(current.error ?? 'فشل Job');
      setResults(current.results);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'فشل تشغيل الفحص');
    } finally {
      setLoading(false);
    }
  }

  async function searchNvd() {
    setNvdError('');
    setNvdData(null);
    setNvdLoading(true);
    try {
      const isCve = /^CVE-\d{4}-\d+$/i.test(nvdQuery.trim());
      const result = await lookupNvd({ asset: target, ...(isCve ? { cve_id: nvdQuery.trim() } : { cpe_name: nvdQuery.trim() }) });
      setNvdData(result);
    } catch (reason) {
      setNvdError(reason instanceof Error ? reason.message : 'تعذر جلب بيانات NVD');
    } finally {
      setNvdLoading(false);
    }
  }

  return <div className="app-shell">
    <header className="topbar">
      <div className="brand-lockup"><div className="brand-mark" aria-hidden="true">A</div><div><p className="eyebrow">DEFENSIVE SECURITY ENGINE</p><h1>AMF <span>Control Room</span></h1></div></div>
      <div className="topbar-meta" role="status" aria-live="polite"><span className={connected ? 'status-dot online' : 'status-dot'} aria-hidden="true" />{loadingInitial ? 'جارٍ تحميل لوحة التحكم' : connected ? 'API متصل' : 'بانتظار API'}<span className={execute ? 'mode-chip live' : 'mode-chip'}>{execute ? 'EXECUTE' : 'DRY-RUN'}</span></div>
    </header>

    <main className="content">
      <section className="hero"><div><p className="eyebrow">AUTHORIZED ASSESSMENT / تقييم مصرّح به</p><h2>رؤية واضحة لما يحدث على سطح الهجوم.</h2><p className="hero-copy">شغّل فحوص AMF، راجع الدليل القابل للتحقق، وافهم الأثر والإصلاح في شاشة واحدة.</p></div><div className="hero-orbit" aria-label="عدد الوحدات المتاحة"><span>11</span><small>modules</small></div></section>

      <section className="workspace-grid">
        <div className="panel scan-panel"><div className="panel-heading"><div><p className="eyebrow">SCAN CONFIGURATION</p><h3>إعداد الفحص</h3></div><span className="lock-badge">ALLOWLIST REQUIRED</span></div>
          <form onSubmit={(event) => { event.preventDefault(); void startScan(); }} aria-busy={loading}>
            <label htmlFor="target">الهدف<input id="target" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://staging.example.com" autoComplete="url" /></label>
            <label htmlFor="allow">التأكيد في القائمة البيضاء<input id="allow" value={allow} onChange={(event) => setAllow(event.target.value)} placeholder="يجب أن يطابق الهدف تمامًا" autoComplete="url" /></label>
            <label htmlFor="profile">Profile<select id="profile" value={profile} onChange={(event) => setProfile(event.target.value)}>{profiles.map((item) => <option key={item.name} value={item.name}>{item.name} · {item.module_count} modules</option>)}</select></label>
            <div className="scan-actions"><label className="toggle-row" htmlFor="execute"><input id="execute" type="checkbox" checked={execute} onChange={(event) => setExecute(event.target.checked)} /><span className="toggle" aria-hidden="true" />السماح بطلبات الشبكة</label><button type="submit" aria-busy={loading} disabled={loading || !target || !allow}>{loading ? 'جارٍ الفحص...' : 'بدء الفحص'}</button></div>
          </form>
          <p className="safety-note" aria-live="polite">{execute ? 'سيتم تنفيذ فحوص محدودة على الهدف المصرّح به فقط.' : 'Dry-run مفعل: لن يتم إرسال أي طلب شبكي.'}</p>{job && loading && <div className="job-progress" role="status" aria-live="polite"><div><span>JOB {job.id.slice(0, 8)}</span><strong>{job.progress}/{job.total || '…'}</strong></div><div className="progress-track" role="progressbar" aria-label="تقدم الفحص" aria-valuemin={0} aria-valuemax={job.total || 1} aria-valuenow={job.progress}><i style={{ width: `${job.total ? (job.progress / job.total) * 100 : 8}%` }} /></div><small>{job.current_module ?? 'في قائمة الانتظار...'}</small></div>}
          {error && <div className="error-box" role="alert" aria-live="assertive"><span>{error}</span><button type="button" className="retry-button" onClick={() => void loadDashboard()}>إعادة المحاولة</button></div>}
        </div>

        <div className="panel evidence-panel"><div className="panel-heading"><div><p className="eyebrow">EVIDENCE-FIRST REPORTING</p><h3>قوة الدليل</h3></div><span className="verified-badge">● منقح وآمن</span></div><div className="evidence-stack"><Evidence label="HTTP status & headers" value="حالة الاستجابة والرؤوس ذات الصلة" /><Evidence label="Confidence" value="ثقة منفصلة عن مستوى الخطورة" /><Evidence label="Impact" value="الأثر المحتمل بلغة مفهومة" /><Evidence label="Sensitive data" value="يظهر النوع والمسار، لا القيمة السرية" /></div></div>
      </section>

      <section className="stats-grid"><Stat label="Modules run" value={results.length || '—'} accent="cyan" /><Stat label="Total findings" value={findings.length || '—'} accent="violet" /><Stat label="High / Critical" value={(counts.high || 0) + (counts.critical || 0)} accent="red" /><Stat label="Medium" value={counts.medium || 0} accent="amber" /></section>

      <section className="panel modules-panel"><div className="panel-heading"><div><p className="eyebrow">MODULE CATALOG</p><h3>الوحدات المتاحة</h3></div><span className="muted">{modules.length} registered modules</span></div><div className="module-grid">{modules.map((module) => <article className="module-card" key={module.name}><div className="module-top"><span className="module-icon" aria-hidden="true">◈</span><span className="risk-pill">{module.risk}</span></div><h4>{module.name}</h4><p>{module.description}</p><div className="tag-row">{module.tags.slice(0, 3).map((tag) => <span key={tag}>#{tag}</span>)}</div></article>)}</div></section>

      <section className="panel results-panel"><div className="panel-heading"><div><p className="eyebrow">FINDINGS / الاكتشافات</p><h3>النتائج مع الدليل والإصلاح</h3></div><span className="muted">{findings.length} findings</span></div>{findings.length === 0 ? <div className="empty-state"><div className="empty-icon" aria-hidden="true">⌁</div><h4>لا توجد نتائج بعد</h4><p>ابدأ Dry-run لمراجعة الوحدات أو فعّل التنفيذ على هدف مصرّح به.</p></div> : <div className="finding-list">{findings.map((finding, index) => <FindingCard key={`${finding.module}-${index}`} finding={finding} />)}</div>}</section>
      <section className="panel intel-panel"><div className="panel-heading"><div><p className="eyebrow">EXTERNAL INTELLIGENCE / NVD</p><h3>مطابقة CVE/CPE تحتاج مراجعة</h3></div><span className="muted">read-only enrichment</span></div><form className="intel-form" onSubmit={(event) => { event.preventDefault(); void searchNvd(); }}><label htmlFor="nvd-query">بحث NVD<input id="nvd-query" value={nvdQuery} onChange={(event) => setNvdQuery(event.target.value)} placeholder="CVE-2024-0001 أو cpe:2.3:a:..." /></label><button type="submit" aria-busy={nvdLoading} disabled={nvdLoading || !target || !nvdQuery.trim()}>{nvdLoading ? 'جارٍ البحث...' : 'بحث في NVD'}</button></form>{nvdError && <div className="error-box" role="alert">{nvdError}</div>}{nvdData && <div className="intel-results" aria-live="polite"><p className="nvd-notice">{nvdData.notice}</p>{nvdData.correlation.observations.length === 0 ? <p className="muted">لم توجد مطابقة في NVD لهذا الاستعلام.</p> : nvdData.correlation.observations.map((observation) => <article className="intel-card" key={observation.value}><div className="intel-card-header"><strong>{observation.value}</strong><span className="risk-pill">potential match / يحتاج مراجعة</span></div><p>{String(observation.evidence.summary ?? '')}</p><div className="intel-meta"><span>CONFIDENCE: {observation.confidence}</span><span>SOURCE: {observation.source}</span><span>RETRIEVED: {observation.observed_at}</span></div><p className="matching-reason">{String(observation.evidence.matching_reason ?? '')}</p>{typeof observation.evidence.source_url === 'string' && <a href={observation.evidence.source_url} target="_blank" rel="noreferrer">فتح مصدر NVD</a>}</article>)}</div>}</section>
    </main>
  </div>;
}

function Evidence({ label, value }: { label: string; value: string }) { return <div className="evidence-row"><span className="evidence-check" aria-hidden="true">✓</span><div><strong>{label}</strong><p>{value}</p></div></div>; }
function Stat({ label, value, accent }: { label: string; value: number | string; accent: string }) { return <div className={`stat-card ${accent}`}><span>{label}</span><strong>{value}</strong><i aria-hidden="true" /></div>; }
function FindingCard({ finding }: { finding: Finding }) { return <article className="finding-card"><div className="finding-header"><div><span className="finding-module">{finding.module}</span><h4>{finding.title_en} <span>/ {finding.title_ar}</span></h4></div><div className={`severity ${finding.severity}`} aria-label={`severity ${finding.severity}`}>{finding.severity}</div></div><div className="finding-grid"><div><span className="field-label">الوصف / DESCRIPTION</span><p>{finding.description_en}</p><p className="arabic-copy">{finding.description_ar}</p></div><div><span className="field-label">الأثر / IMPACT</span><p>{finding.impact_en || 'See the finding description.'}</p><p className="arabic-copy">{finding.impact_ar || 'راجع وصف الاكتشاف.'}</p></div><div><span className="field-label">الإصلاح / REMEDIATION</span><p>{finding.remediation_en}</p><p className="arabic-copy">{finding.remediation_ar}</p></div><div><span className="field-label">الدليل / EVIDENCE</span><pre>{JSON.stringify(finding.evidence, null, 2)}</pre></div></div><div className="finding-footer"><span>TYPE: {finding.type}</span><span>CONFIDENCE: {finding.confidence}</span></div></article>; }
