import { useEffect, useMemo, useRef, useState } from 'react';

export type Verdict = 'ATTACK' | 'SUSPICIOUS' | 'FAULT';
export type Mark = { start: number; end: number; verdict: Verdict; label: string; shape: 'ring' | 'bracket' };
type Trace = { duration: number; counts: number[] };

const vClass = (v: Verdict) => (v === 'ATTACK' ? 'v-attack' : v === 'FAULT' ? 'v-fault' : 'v-susp');

/* deterministic "hand" jitter so grease marks look drawn, not computed */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function smoothPath(pts: [number, number][]) {
  if (pts.length < 2) return '';
  let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[Math.max(0, i - 1)], p1 = pts[i], p2 = pts[i + 1], p3 = pts[Math.min(pts.length - 1, i + 2)];
    const c1x = p1[0] + (p2[0] - p0[0]) / 6, c1y = p1[1] + (p2[1] - p0[1]) / 6;
    const c2x = p2[0] - (p3[0] - p1[0]) / 6, c2y = p2[1] - (p3[1] - p1[1]) / 6;
    d += ` C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
  }
  return d;
}

function wobblyRing(cx: number, cy: number, rx: number, ry: number, seed: number) {
  const r = rng(seed);
  const pts: [number, number][] = [];
  const tilt = (r() - 0.5) * 0.12;
  const steps = 40;
  for (let i = 0; i <= steps + 5; i++) {               // overshoot: a hand never closes exactly
    const t = (i / steps) * Math.PI * 2 - 0.6;
    const k = 1 + (r() - 0.5) * 0.06 + (i > steps ? 0.05 : 0);
    const x = Math.cos(t) * rx * k, y = Math.sin(t) * ry * k;
    pts.push([cx + x * Math.cos(tilt) - y * Math.sin(tilt), cy + x * Math.sin(tilt) + y * Math.cos(tilt)]);
  }
  return pts;
}

function length(pts: [number, number][]) {
  let L = 0;
  for (let i = 1; i < pts.length; i++) L += Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]);
  return Math.ceil(L * 1.08);
}

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [w, setW] = useState(1200);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([e]) => setW(e.contentRect.width));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w] as const;
}

export function useInView<T extends HTMLElement>(threshold = 0.35) {
  const ref = useRef<T>(null);
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setSeen(true); io.disconnect(); } }, { threshold });
    io.observe(el);
    return () => io.disconnect();
  }, [threshold]);
  return [ref, seen] as const;
}

type Props = {
  trace: Trace;
  marks: Mark[];
  labelLeft: React.ReactNode;
  labelRight?: React.ReactNode;
  aspect?: number;          // height / width at desktop
  seed?: number;
  title: string;
};

export default function Film({ trace, marks, labelLeft, labelRight, aspect = 0.27, seed = 7, title }: Props) {
  const [box, width] = useWidth<HTMLDivElement>();
  const [host, seen] = useInView<HTMLDivElement>(0.3);
  const narrow = width < 640;
  // narrow screens get a taller frame in fewer units so the marker text stays legible
  const W = narrow ? 640 : 1200;
  const H = Math.round(W * (narrow ? Math.max(aspect * 1.9, 0.5) : aspect));
  const top = narrow ? 64 : 58, base = H - (narrow ? 70 : 54);

  const geo = useMemo(() => {
    const c = trace.counts, n = c.length, max = Math.max(...c, 1);
    const x = (i: number) => 18 + (i / (n - 1)) * (W - 36);
    const y = (v: number) => base - Math.sqrt(v / max) * (base - top);
    const pts: [number, number][] = c.map((v, i) => [x(i), y(v)]);
    const line = smoothPath(pts);
    const area = `${line} L${x(n - 1).toFixed(1)},${base} L${x(0).toFixed(1)},${base} Z`;
    const tx = (s: number) => 18 + (s / trace.duration) * (W - 36);
    const step = trace.duration > 30 ? 10 : 5;
    const ticks: number[] = [];
    for (let s = 0; s <= trace.duration; s += step) ticks.push(s);
    const peakIn = (s0: number, s1: number) => {
      const i0 = Math.max(0, Math.floor((s0 / trace.duration) * (n - 1)));
      const i1 = Math.min(n - 1, Math.ceil((s1 / trace.duration) * (n - 1)));
      let m = 0;
      for (let i = i0; i <= i1; i++) m = Math.max(m, c[i]);
      return y(m);
    };
    return { line, area, tx, ticks, peakIn };
  }, [trace, W, base, top]);

  const fs = narrow ? 34 : 30;
  return (
    <div className="film-host" ref={host}>
      <div className="clips" aria-hidden="true"><span className="clip" /><span className="clip" /></div>
      <div className={`film ${seen ? 'inview' : ''}`} ref={box}>
        <svg className="trace" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={title}>
          <title>{title}</title>
          <defs>
            <linearGradient id={`tissue-${seed}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor="#f2f8fc" stopOpacity="0.55" />
              <stop offset="0.6" stopColor="#9fb8c8" stopOpacity="0.16" />
              <stop offset="1" stopColor="#9fb8c8" stopOpacity="0" />
            </linearGradient>
            <filter id={`bloom-${seed}`} x="-10%" y="-40%" width="120%" height="180%">
              <feGaussianBlur stdDeviation="7" />
            </filter>
          </defs>
          {geo.ticks.map((s) => (
            <g key={s}>
              <line x1={geo.tx(s)} x2={geo.tx(s)} y1={26} y2={base} stroke="#8fa6b8" strokeOpacity="0.13" />
              <text x={geo.tx(s) + 5} y={22} fill="#8fa6b8" fontFamily="JetBrains Mono" fontSize={narrow ? 17 : 13}>{s}s</text>
            </g>
          ))}
          <line x1={18} x2={W - 18} y1={base} y2={base} stroke="#8fa6b8" strokeOpacity="0.25" />
          <path d={geo.area} fill={`url(#tissue-${seed})`} />
          <path d={geo.line} fill="none" stroke="#e6f0f7" strokeWidth="9" strokeOpacity="0.35" filter={`url(#bloom-${seed})`} />
          <path d={geo.line} fill="none" stroke="#f4f9fc" strokeWidth="1.8" />

          {marks.map((m, i) => {
            const x0 = geo.tx(m.start), x1 = geo.tx(m.end), cls = vClass(m.verdict), d = `${0.35 + i * 0.55}s`;
            if (m.shape === 'ring') {
              const cx = (x0 + x1) / 2, rx = Math.max((x1 - x0) / 2 + 26, narrow ? 46 : 40);
              const pk = geo.peakIn(m.start, m.end);
              const cy = (pk + base) / 2 - 4, ry = Math.max((base - pk) / 2 + 22, 34);
              const pts = wobblyRing(cx, cy, rx, ry, seed * 31 + i);
              const right = cx < W * 0.62;
              const lx = right ? cx + rx + 14 : cx - rx - 14;
              return (
                <g key={i}>
                  <path className={`grease ${cls}`} style={{ ['--len' as string]: length(pts), ['--d' as string]: d }} d={smoothPath(pts)} />
                  <text className={`grease-note ${cls}`} style={{ ['--d' as string]: `${0.9 + i * 0.55}s` }}
                        x={lx} y={Math.max(cy - ry + 18, top + 8)} fontSize={fs} textAnchor={right ? 'start' : 'end'}>{narrow ? m.label.split(' · ')[0] : m.label}</text>
                </g>
              );
            }
            const r = rng(seed * 17 + i);
            const yb = base + (narrow ? 22 : 18);
            const pts: [number, number][] = [[x0, yb - 14]];
            for (let k = 0; k <= 10; k++) pts.push([x0 + ((x1 - x0) * k) / 10, yb + (r() - 0.5) * 3]);
            pts.push([x1, yb - 14]);
            const mid = (x0 + x1) / 2;
            return (
              <g key={i}>
                <path className={`grease ${cls}`} style={{ ['--len' as string]: length(pts), ['--d' as string]: d }} d={smoothPath(pts)} />
                <text className={`grease-note ${cls}`} style={{ ['--d' as string]: `${0.9 + i * 0.55}s` }}
                      x={Math.min(Math.max(mid, 120), W - 120)} y={yb + (narrow ? 42 : 34)} fontSize={fs - 4} textAnchor="middle">{m.label}</text>
              </g>
            );
          })}
        </svg>
        <div className="film-strip"><span>{labelLeft}</span>{labelRight && <span>{labelRight}</span>}</div>
      </div>
    </div>
  );
}
