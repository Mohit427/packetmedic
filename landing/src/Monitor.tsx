import { useEffect, useState } from 'react';
import data from './data.json';

/* Bedside monitor showing real pmtui screens with their real colours
   (tools/landing_data.py exports them from `pmtui --snapshot`). */
type Run = [number, number, number, number, string];
type Frame = { label: string; rows: Run[][] };

const FRAMES = data.pmtui_frames as unknown as Frame[];
const ROWS = 18;                               // the part of the 80x24 screen the casing shows
const HOLD = [2000, 2000, 3000, 3000];         // 10 second loop
const KEYS = ['Menu', 'Samples', 'Attack', 'Fault'];

const PALETTE = ['#0b1016', '#c50f1f', '#22b14c', '#c19c00', '#0037da', '#881798', '#3a96dd', '#cccccc',
  '#767676', 'var(--attack)', '#6ee787', 'var(--suspicious)', 'var(--fault)', '#b4009e', '#61d6d6', '#f2f2f2'];
const color = (c: number, fallback: string) => (c >= 0 && c < 16 ? PALETTE[c] : fallback);

function Screen({ frame }: { frame: Frame }) {
  return (
    <div className="mon-screen">
      {frame.rows.slice(0, ROWS).map((row, y) => (
        <div className="mon-row" key={y}>
          {row.map(([col, fg, bg, attr, text], i) => (
            <span key={i} style={{
              left: `${col * 0.6}em`, width: `${text.length * 0.6}em`, color: color(fg, '#cfd8e0'),
              background: bg >= 0 ? color(bg, 'transparent') : undefined,
              fontWeight: attr & 1 ? 600 : 400, textDecoration: attr & 2 ? 'underline' : undefined,
            }}>{text}</span>
          ))}
        </div>
      ))}
    </div>
  );
}

export default function Monitor() {
  const reduced = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
  const [i, setI] = useState(reduced ? 2 : 0);
  useEffect(() => {
    if (reduced) return;
    const t = setTimeout(() => setI((n) => (n + 1) % FRAMES.length), HOLD[i]);
    return () => clearTimeout(t);
  }, [i, reduced]);

  return (
    <figure className="monitor" role="img"
      aria-label="A bedside patient monitor running pmtui, cycling through its menu, sample browser, and the attack and fault findings for the mixed sample capture.">
      <div className="mon-top" aria-hidden="true">
        <span className="mon-led" />
        <span className="mon-name">pmtui</span>
        <svg className="mon-ecg" viewBox="0 0 240 20" preserveAspectRatio="none">
          <g className="mon-ecg-run">
            {[0, 120, 240].map((x) => (
              <path key={x} transform={`translate(${x} 0)`} d="M0 12 H42 L47 9 L52 12 H60 L64 15 L69 2 L74 18 L78 12 H88 L95 8 L102 12 H120" />
            ))}
          </g>
        </svg>
        <span className="mon-real">real output</span>
      </div>
      <Screen frame={FRAMES[i]} />
      <div className="mon-keys" aria-hidden="true">
        {KEYS.map((k, n) => <span key={k} className={n === i ? 'on' : ''}>{k}</span>)}
      </div>
    </figure>
  );
}
