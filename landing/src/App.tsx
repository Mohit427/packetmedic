import { useEffect, useState } from 'react';
import { Activity, Check, Copy, Download, ExternalLink, Github, MonitorPlay, ShieldCheck, TriangleAlert } from 'lucide-react';
import Film, { type Mark, type Verdict, useInView } from './Film';
import DecryptedText from './reactbits/DecryptedText';
import CountUp from './reactbits/CountUp';
import Noise from './reactbits/Noise';
import SpotlightCard from './reactbits/SpotlightCard';
import data from './data.json';

const REPO = 'https://github.com/Mohit427/packetmedic';
const R = data.release;

type Inc = {
  id: string; kind: string; verdict: string; confidence: string; title: string; summary: string; cause: string;
  steps: string[]; start: number; end: number; frames: number; filter: string;
  attack_score: number; fault_score: number; for_attack: string[]; for_fault: string[];
};
type Rep = { file: string; packets: number; duration: number; trace: { duration: number; counts: number[] }; incidents: Inc[] };

function demoHref(): string {
  try {
    return new URL('/demo', window.top!.location.href).toString();
  } catch {
    return 'https://packetmedic.streamlit.app/demo';
  }
}

/* Streamlit's embed sandbox forbids top-level navigation from inside the frame,
   but the frame is same-origin: click a link created in the host page instead,
   falling back to a new tab. */
function openInHost(e: React.MouseEvent<HTMLAnchorElement>) {
  const href = e.currentTarget.href;
  for (const w of [window.top, window.parent]) {
    try {
      if (!w || w === window) continue;
      const a = w.document.createElement('a');
      a.href = href;
      w.document.body.appendChild(a);
      a.click();
      a.remove();
      e.preventDefault();
      return;
    } catch {
      /* not reachable: try the next one */
    }
  }
  if (window.top !== window) { e.preventDefault(); window.open(href, '_blank', 'noopener'); }
}

function go(id: string) {
  return (e: React.MouseEvent) => {
    e.preventDefault();
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
}

const vcol = (v: string) => (v === 'ATTACK' ? 'var(--attack)' : v === 'FAULT' ? 'var(--fault)' : 'var(--suspicious)');

function Tabs({ dark = false }: { dark?: boolean }) {
  const [demo, setDemo] = useState('https://packetmedic.streamlit.app/demo');
  useEffect(() => setDemo(demoHref()), []);
  return (
    <div className="tabs">
      <a className={`tab ${dark ? 'tab-light' : 'tab-primary'}`} href={R.direct} target="_blank" rel="noopener">
        <Download size={22} strokeWidth={2.4} aria-hidden="true" /> Download for Windows
        <small>{R.size_mb} MB zip</small>
      </a>
      <a className={`tab ${dark ? 'tab-ghost' : 'tab-secondary'}`} href={demo} target="_top" onClick={openInHost}>
        <MonitorPlay size={22} strokeWidth={2.2} aria-hidden="true" /> Open the web demo
      </a>
    </div>
  );
}

/* ------------------------------------------------------------------ hero */
function Hero() {
  const [on, setOn] = useState(false);
  useEffect(() => { const t = setTimeout(() => setOn(true), 120); return () => clearTimeout(t); }, []);
  const m = data.mixed;
  const marks: Mark[] = m.incidents.map((i: Inc) => ({
    start: i.start, end: i.end, verdict: i.verdict as Verdict, shape: i.verdict === 'ATTACK' ? 'ring' : 'bracket',
    label: i.verdict === 'ATTACK' ? 'ATTACK · port scan' : 'FAULT · DNS server not answering',
  }));
  return (
    <div className="wrap">
      <div className="lightbox">
        <div className={`lightbox-panel ${on ? 'on' : ''}`}>
          <div className="hero-head">
            <h1 className="hero-title"><span>Same broken network.</span><span className="second">Two different diagnoses.</span></h1>
            <p className="hero-sub">
              PacketMedic reads a packet capture the way a radiologist reads a scan. It finds the <strong>faults</strong> and
              the <strong>attacks</strong> hidden in the traffic, tells you which is which, and points at the exact packets.
            </p>
          </div>
          <div className="hero-film-wrap">
            <SpotlightCard className="film-spot" theme="dark" spotlightColor="rgba(225, 238, 250, 0.22)" spotlightSize={340} borderGlow={0} grain={0}>
              <div style={{ position: 'relative' }}>
                <Film
                  trace={m.trace}
                  marks={marks}
                  seed={11}
                  aspect={0.25}
                  title="Packets per moment in the mixed outage and attack sample, with the port scan and the DNS outage marked"
                  labelLeft={<><b>{m.file}</b> · {m.packets} packets · {m.duration} s</>}
                  labelRight={<>synthetic sample · read by PacketMedic {data.version}</>}
                />
                <Noise opacity={0.07} size={2} fps={14} blendMode="screen" dust={0.25} scratches={0.12} />
              </div>
            </SpotlightCard>
          </div>
          <div className="hero-actions">
            <Tabs />
            <p className="hero-note">
              The terminal app is the product: offline, with live capture. The web demo runs the same engine on sample captures.{' '}
              <a href="#windows" onClick={go('windows')}>Windows may warn you, here is why.</a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ the read */
function Read() {
  const pk = data.poison_packet;
  const inc = data.arp_spoof.incidents[0];
  const [ref, seen] = useInView<HTMLDivElement>(0.25);
  const max = Math.max(inc.attack_score, inc.fault_score, 1);
  return (
    <section id="read" className="sec">
      <div className="wrap">
        <div className="sec-head">
          <h2 className="sec-title">From raw bytes to a verdict.</h2>
          <p className="sec-lede">
            This is the real first forged packet from the ARP spoofing sample, followed through PacketMedic. <strong>No AI model
            and no cloud call</strong>: protocol rules, remembered state and weighed evidence.
          </p>
        </div>
        <div className={`bank ${seen ? 'inview' : ''}`} ref={ref}>
          <div className="cell"><div className="cell-in dark">
            <div className="t"><span>frame {pk.frame}</span><span>raw bytes</span></div>
            <p className="hex">
              <DecryptedText text={pk.hex} animateOn="view" sequential revealDirection="start" speed={14}
                characters="0123456789abcdef" useOriginalCharsOnly={false} encryptedClassName="enc" />
            </p>
            <p>{pk.decoded}</p>
          </div></div>
          <div className="cell"><div className="cell-in">
            <div className="t"><span>decoded</span><span>ARP reply</span></div>
            <h3>Nobody asked.</h3>
            <dl className="kv">
              <dt>claims ip</dt><dd>{pk.fields.claims_ip}</dd>
              <dt>claims mac</dt><dd>{pk.fields.claims_mac}</dd>
              <dt>sent to</dt><dd>{pk.fields.sent_to}</dd>
            </dl>
            <p style={{ marginTop: 12 }}>The tracker remembers that {pk.fields.claims_ip} already belonged to a different device, and that no one requested this reply.</p>
          </div></div>
          <div className="cell"><div className="cell-in">
            <div className="t"><span>weighed</span><span>attack vs fault</span></div>
            <h3>Evidence, not vibes.</h3>
            <div className="weights">
              <div className="wrow"><span>attack</span><span className="wbar"><i className="a" style={{ ['--w' as string]: `${(inc.attack_score / max) * 100}%` }} /></span><span className="num">{inc.attack_score.toFixed(1)}</span></div>
              <div className="wrow"><span>fault</span><span className="wbar"><i className="f" style={{ ['--w' as string]: `${(inc.fault_score / max) * 100}%` }} /></span><span className="num">{inc.fault_score.toFixed(1)}</span></div>
            </div>
            <p style={{ marginTop: 14 }}>{inc.for_attack.length} reasons point to an attack, among them: {inc.for_attack[2]?.toLowerCase()}</p>
          </div></div>
          <div className="cell"><div className="cell-in">
            <div className="t"><span>explained</span><span>{inc.confidence} confidence</span></div>
            <h3>{inc.title.split(':')[0]}.</h3>
            <p>{inc.cause}</p>
            <p style={{ marginTop: 10 }}><b>First step:</b> {inc.steps[0]}</p>
            <span className="verdict-stamp" style={{ color: vcol(inc.verdict) }}>{inc.verdict}</span>
          </div></div>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ fault vs attack */
function Case({ rep, title, label }: { rep: Rep; title: string; label: string }) {
  const inc = rep.incidents[0];
  const v = inc.verdict as Verdict;
  const pts = v === 'ATTACK' ? inc.for_attack.slice(0, 4) : inc.for_fault;
  const s = Math.max(0.5, Math.min(inc.start, rep.trace.duration - 2));
  return (
    <div className="case">
      <Film trace={rep.trace} seed={v === 'ATTACK' ? 7 : 4} aspect={0.36}
        marks={[{ start: s, end: Math.min(inc.end, rep.trace.duration), verdict: v, shape: 'bracket', label }]}
        title={`${rep.file}: ${inc.title}`}
        labelLeft={<><b>{rep.file}</b></>} labelRight={<>{rep.packets} packets · synthetic</>} />
      <h3 className="case-title">{title}</h3>
      <p className="case-sym">{inc.summary.split('. ').slice(0, 2).join('. ')}.</p>
      <ul className="points">
        {pts.map((p: string, i: number) => (
          <li key={i}>
            {v === 'ATTACK'
              ? <TriangleAlert size={18} color="var(--attack)" aria-label="points to attack" />
              : <Check size={18} color="var(--fault)" aria-label="points to fault" />}
            <span>{p}</span>
          </li>
        ))}
      </ul>
      <p className="score num">attack evidence <b style={{ color: 'var(--attack)' }}>{inc.attack_score.toFixed(1)}</b> · fault evidence <b style={{ color: 'var(--fault)' }}>{inc.fault_score.toFixed(1)}</b> · verdict <b style={{ color: vcol(v) }}>{v}</b></p>
    </div>
  );
}

function Verdicts() {
  return (
    <section id="verdicts" className="sec">
      <div className="wrap">
        <div className="sec-head">
          <h2 className="sec-title">Same symptom. Opposite verdicts.</h2>
          <p className="sec-lede">
            In both captures one IP address is claimed by two different devices. To a user both look like "the network keeps
            dropping". PacketMedic weighs the evidence for each explanation and <strong>shows its work</strong>.
          </p>
        </div>
        <div className="bank bank-2" style={{ gap: 'clamp(28px, 4vw, 56px)' }}>
          <Case rep={data.duplicate_ip as Rep} title="A typo in someone's settings" label="FAULT · duplicate IP" />
          <Case rep={data.arp_spoof as Rep} title="Someone in the middle" label="ATTACK · ARP spoofing" />
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ product */
function TermLine({ line, i }: { line: string; i: number }) {
  if (i === 0) return <span className="hdr">{line}</span>;
  const parts = line.split(/(ATTACK|FAULT|Under attack)/);
  return (
    <>
      {parts.map((p, k) =>
        p === 'ATTACK' || p === 'Under attack' ? <span key={k} className="a">{p}</span>
          : p === 'FAULT' ? <span key={k} className="f">{p}</span> : <span key={k}>{p}</span>,
      )}
    </>
  );
}

function Product() {
  const lines = data.pmtui.slice(0, 24);
  return (
    <section id="product" className="sec">
      <div className="wrap">
        <div className="sec-head">
          <h2 className="sec-title">The product is the terminal.</h2>
          <p className="sec-lede">
            <strong>pmtui</strong> is a native C, htop-style dashboard. It analyses the samples and your own captures, and it
            records live traffic from your machine, all offline. Below is its real output for the capture on the lightbox above.
          </p>
        </div>
        <div className="product">
          <div className="cell"><div className="cell-in dark" style={{ padding: 0 }}>
            <pre className="term" aria-label="pmtui dashboard output">{lines.map((l, i) => <span key={i}><TermLine line={l} i={i} />{'\n'}</span>)}</pre>
          </div></div>
          <div>
            <table className="compare">
              <thead><tr><th scope="col"><span className="sr-only">Capability</span></th><th scope="col">pmtui app</th><th scope="col" className="demo">Web demo</th></tr></thead>
              <tbody>
                <tr><td>Bundled sample captures</td><td className="yes">Yes</td><td className="demo">Yes</td></tr>
                <tr><td>Your own .pcap / .pcapng</td><td className="yes">Yes, stays on your machine</td><td className="demo">Uploaded to a cloud server</td></tr>
                <tr><td>Live capture (5 to 300 s)</td><td className="yes">Yes, passive, after consent</td><td className="no">No: a server can't see your network</td></tr>
                <tr><td>Works offline</td><td className="yes">Yes</td><td className="no">No</td></tr>
                <tr><td>HTML / JSON report, evidence .pcap</td><td className="yes">Yes</td><td className="demo">Yes</td></tr>
                <tr><td>Install</td><td className="yes">Unzip and run</td><td className="demo">None</td></tr>
              </tbody>
            </table>
            <p className="demo-note"><strong>The web demo is for demonstration only.</strong> It exists so you can try the engine in a browser in ten seconds. For a real network, use the app.</p>
            <div style={{ marginTop: 22 }}><Tabs dark /></div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ windows */
function Windows() {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    const txt = R.sha256 ?? '';
    try { await navigator.clipboard.writeText(txt); }
    catch {
      const ta = document.createElement('textarea');
      ta.value = txt; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch { /* user can select manually */ }
      ta.remove();
    }
    setCopied(true); setTimeout(() => setCopied(false), 1800);
  };
  return (
    <section id="windows" className="sec">
      <div className="wrap">
        <div className="sec-head">
          <h2 className="sec-title">Windows will probably warn you.</h2>
          <p className="sec-lede">
            PacketMedic is a hackathon build without a paid code-signing certificate, so Windows treats it as an unknown app.
            Here is what you may see, <strong>why it happens</strong>, and how to check the file is the one we published.
          </p>
        </div>
        <div className="win">
          <div className="cell"><div className="cell-in">
            <div className="t"><span>expected</span><span>Microsoft Defender SmartScreen</span></div>
            <h3>"Windows protected your PC"</h3>
            <p>This blue screen appears for any app that isn't code-signed and hasn't been downloaded by many people yet. It is a reputation check, not a virus detection.</p>
            <ol className="steps">
              <li><span>Click <span className="kbd">More info</span>.</span></li>
              <li><span>Check the file name is <span className="kbd">pmtui.exe</span>, then click <span className="kbd">Run anyway</span>.</span></li>
              <li><span>For live capture, open Terminal with <span className="kbd">Run as administrator</span> first: Windows' packet monitor requires it.</span></li>
            </ol>
          </div></div>
          <div className="cell"><div className="cell-in dark">
            <div className="t"><span>possible</span><span>Microsoft Defender Antivirus</span></div>
            <h3>A false-positive flag</h3>
            <p>The engine is bundled with PyInstaller, which unpacks a Python runtime when it starts. Antivirus heuristics sometimes flag such apps, often under generic names. We have not seen Defender flag PacketMedic in our own tests, but if it does:</p>
            <ol className="steps">
              <li><span>First verify the zip's checksum (below). If it doesn't match, delete the file.</span></li>
              <li><span>Open <span className="kbd">Windows Security</span> → <span className="kbd">Virus &amp; threat protection</span> → <span className="kbd">Protection history</span>.</span></li>
              <li><span>Select the PacketMedic entry → <span className="kbd">Actions</span> → <span className="kbd">Allow on device</span> (or <span className="kbd">Restore</span>).</span></li>
            </ol>
            <p style={{ marginTop: 12 }}>Never switch Defender off to run it. Allow only this one file, only after the checksum matches.</p>
          </div></div>
        </div>
        <div style={{ marginTop: 'var(--cell-gap)' }}>
          <p className="sec-lede" style={{ maxWidth: 'none' }}>Check the download in PowerShell with <span className="kbd" style={{ background: 'var(--wall-2)', color: 'var(--wall-text)' }}>Get-FileHash .\{R.file} -Algorithm SHA256</span>. It must print exactly:</p>
          <div className="hash">
            <code aria-label="SHA-256 checksum">{R.sha256}</code>
            <button className="copy" onClick={copy} type="button">
              {copied ? <Check size={18} aria-hidden="true" /> : <Copy size={18} aria-hidden="true" />} {copied ? 'Copied' : 'Copy hash'}
            </button>
          </div>
          <ul className="honest">
            <li><ShieldCheck size={18} aria-hidden="true" /><span>Sends nothing over the network: no telemetry, no AI or cloud calls.</span></li>
            <li><ShieldCheck size={18} aria-hidden="true" /><span>Captures traffic only after you confirm on the consent screen, for 5 to 300 seconds.</span></li>
            <li><ShieldCheck size={18} aria-hidden="true" /><span>Captures and reports stay in its own folder on your machine.</span></li>
            <li><ShieldCheck size={18} aria-hidden="true" /><span>Rather not run an unsigned app? Build it from the <a href={REPO} target="_blank" rel="noopener">source on GitHub</a> or try the web demo.</span></li>
          </ul>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ lab report */
function Report() {
  const e = data.eval;
  const [ref, seen] = useInView<HTMLDivElement>(0.4);
  const rows: [React.ReactNode, string][] = [
    [<><CountUp to={e.verdicts_right} trigger="view" duration={1.2} />/{e.verdicts_total}</>, 'fault-vs-attack verdicts correct'],
    [<CountUp to={e.false_alarms} trigger="view" duration={0.6} />, 'false alarms on the labelled samples'],
    [<CountUp to={data.tests} trigger="view" duration={1.4} />, 'automated tests, incl. real Wi-Fi capture quirks'],
    [<CountUp to={data.fuzz_cases} trigger="view" duration={1.3} />, 'fuzz cases: corrupt, truncated and hostile files'],
    [<CountUp to={0} trigger="view" duration={0.4} />, 'AI model or cloud calls'],
  ];
  return (
    <section id="report" className="sec" ref={ref}>
      <div className="wrap">
        <div className="sec-head">
          <h2 className="sec-title">Measured, and labelled honestly.</h2>
          <p className="sec-lede">
            Results from running PacketMedic on its {e.samples} labelled sample captures and its test suite.
          </p>
        </div>
        <div className="report">
          {rows.map(([v, l], i) => <div key={i}><div className="v num">{seen ? v : '0'}</div><div className="l">{l}</div></div>)}
        </div>
        <p className="fine">
          The sample captures are synthetic, generated packet by packet to simulate a small office network, so these numbers
          are a regression check, not a real-world benchmark. A live capture on our own Wi-Fi also caught a harmless,
          self-generated port scan and DNS failures, plus a real lossy Chromecast connection.
        </p>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ page */
export default function App() {
  return (
    <>
      <nav className="nav" aria-label="Main">
        <div className="wrap">
          <a className="brand" href="#top" onClick={go('top')}><Activity size={24} strokeWidth={2.6} aria-hidden="true" />PacketMedic</a>
          <div className="nav-links">
            <a href="#read" onClick={go('read')}>How it reads</a>
            <a href="#verdicts" onClick={go('verdicts')}>Fault or attack</a>
            <a href="#product" onClick={go('product')}>The app</a>
            <a href="#windows" onClick={go('windows')}>Windows warning</a>
            <a className="nav-gh" href={REPO} target="_blank" rel="noopener"><Github size={17} aria-hidden="true" /> GitHub</a>
          </div>
        </div>
      </nav>
      <main id="top">
        <Hero />
        <Read />
        <Verdicts />
        <Product />
        <Windows />
        <Report />
        <section className="close">
          <div className="wrap">
            <div className="lightbox"><div className="lightbox-panel">
              <div>
                <h2>Read your own network.</h2>
                <p>Unzip, run <b>pmtui.exe</b>, press 3, and give it thirty seconds of your traffic. Everything stays on your machine.</p>
              </div>
              <Tabs />
            </div></div>
          </div>
        </section>
      </main>
      <footer>
        <div className="wrap">
          <span>PacketMedic {data.version} · Team <b>Three Pointers</b> · 24h Cybersecurity Hackathon, IIITDM Kancheepuram</span>
          <span><a href={REPO} target="_blank" rel="noopener">Source</a> · <a href={R.url} target="_blank" rel="noopener">Releases</a> · <a href={`${REPO}/blob/main/docs/CLI_ARCHITECTURE.md`} target="_blank" rel="noopener">Architecture</a></span>
        </div>
      </footer>
    </>
  );
}
