"""Self-contained HTML report (no external resources, works offline).

Rendered with Jinja2 autoescaping ON: every value that came from a packet
(DNS names, etc.) is HTML-escaped, so a hostile capture cannot inject script.
"""
from __future__ import annotations

from jinja2 import Environment, select_autoescape

_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>PacketMedic Report</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2433;--muted:#5d6678;--line:#e2e5eb;
--attack:#c62828;--attack-bg:#fdecec;--sus:#b26a00;--sus-bg:#fff4e0;--fault:#1f5fbf;--fault-bg:#e8f0fc;--ok:#2e7d32}
@media (prefers-color-scheme: dark){:root{--bg:#12151c;--card:#1b1f29;--ink:#e6e9ef;--muted:#9aa3b5;--line:#2b3140;
--attack:#ff6b6b;--attack-bg:#3a1f22;--sus:#ffb74d;--sus-bg:#3a2c16;--fault:#7fb0ff;--fault-bg:#1c2a42;--ok:#81c784}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:24px 16px 60px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 12px}
.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:16px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.stat b{display:block;font-size:22px}.score{font-size:40px;font-weight:700}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:14px 0;border-left:5px solid var(--fault)}
.card.ATTACK{border-left-color:var(--attack)}.card.SUSPICIOUS{border-left-color:var(--sus)}
.badge{display:inline-block;font-size:12px;font-weight:700;padding:2px 8px;border-radius:999px;margin-right:6px}
.badge.ATTACK{background:var(--attack-bg);color:var(--attack)}.badge.SUSPICIOUS{background:var(--sus-bg);color:var(--sus)}
.badge.FAULT{background:var(--fault-bg);color:var(--fault)}.badge.meta{background:var(--bg);color:var(--muted)}
.card h3{margin:8px 0 6px;font-size:17px}code{background:var(--bg);padding:2px 6px;border-radius:5px;font-size:13px;word-break:break-all}
ul{margin:6px 0 6px 20px;padding:0}.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media (max-width:640px){.cols{grid-template-columns:1fr}}
.pt{font-size:13px}.label{font-weight:600;margin-top:10px}
.tl{position:relative;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.tlrow{display:flex;align-items:center;gap:10px;margin:4px 0;font-size:13px}.tlrow span.id{width:62px;flex:none}
.track{position:relative;flex:1;height:14px;background:var(--bg);border-radius:4px}
.bar{position:absolute;top:0;height:14px;border-radius:4px;min-width:4px;background:var(--fault)}
.bar.ATTACK{background:var(--attack)}.bar.SUSPICIOUS{background:var(--sus)}
.warn{background:var(--sus-bg);color:var(--ink);border-radius:8px;padding:8px 12px;margin:6px 0;font-size:14px}
footer{margin-top:40px;font-size:13px;color:var(--muted)}
</style></head><body><div class="wrap">
<h1>PacketMedic Report</h1>
<div class="muted">{{ r.file.name }} &middot; {{ r.capture.packets }} packets &middot; {{ "%.1f"|format(r.capture.duration_s) }} s
 &middot; {{ r.capture.hosts_seen }} hosts{% if r.anonymized %} &middot; addresses anonymized{% endif %}</div>
<div class="grid">
 <div class="stat"><span class="muted">Network health</span><span class="score">{{ r.health.score }}</span><span class="muted"> / 100 &middot; {{ r.health.label }}</span></div>
 <div class="stat"><span class="muted">Attacks</span><b style="color:var(--attack)">{{ r.counts.ATTACK }}</b></div>
 <div class="stat"><span class="muted">Suspicious</span><b style="color:var(--sus)">{{ r.counts.SUSPICIOUS }}</b></div>
 <div class="stat"><span class="muted">Faults</span><b style="color:var(--fault)">{{ r.counts.FAULT }}</b></div>
</div>
{% for w in r.warnings %}<div class="warn">&#9888; {{ w }}</div>{% endfor %}
{% if r.incidents %}
<h2>Timeline</h2><div class="tl">
{% set dur = r.capture.duration_s if r.capture.duration_s > 0 else 1 %}
{% for i in r.incidents %}<div class="tlrow"><span class="id">{{ i.id }}</span><div class="track">
<div class="bar {{ i.verdict }}" style="left:{{ (100*i.start_offset_s/dur)|round(2) }}%;width:{{ [100*(i.end_offset_s-i.start_offset_s)/dur, 0.5]|max|round(2) }}%"></div></div></div>{% endfor %}
</div>
<h2>Findings</h2>
{% for i in r.incidents %}
<div class="card {{ i.verdict }}">
 <span class="badge {{ i.verdict }}">{{ i.verdict }}</span><span class="badge meta">{{ i.id }}</span>
 <span class="badge meta">confidence: {{ i.confidence }}</span><span class="badge meta">severity: {{ i.severity }}</span>
 <h3>{{ i.title }}</h3>
 <p>{{ i.summary }}</p>
 <div class="cols">
  <div><div class="label">Why it matters</div><div>{{ i.why_it_matters }}</div>
       <div class="label">Likely cause</div><div>{{ i.likely_cause }}</div></div>
  <div><div class="label">What to do next</div><ul>{% for s in i.next_steps %}<li>{{ s }}</li>{% endfor %}</ul></div>
 </div>
 <div class="label">Why PacketMedic thinks this is {{ "an attack" if i.verdict == "ATTACK" else "suspicious" if i.verdict == "SUSPICIOUS" else "a fault" }}
  <span class="muted pt">(attack evidence {{ i.reasoning.attack_score }} vs fault evidence {{ i.reasoning.fault_score }})</span></div>
 <ul class="pt">{% for p in i.reasoning.points_for_attack %}<li>&#9888; {{ p.text }}</li>{% endfor %}
 {% for p in i.reasoning.points_for_fault %}<li>&#10003; {{ p.text }}</li>{% endfor %}</ul>
 <div class="label">Evidence</div>
 <div class="pt">Frames: {{ i.evidence_frames[:30]|join(", ") }}{% if i.evidence_frames|length > 30 %} &hellip; ({{ i.evidence_frames|length }} total){% endif %}</div>
 <div class="pt">Wireshark filter: <code>{{ i.wireshark_filter }}</code></div>
</div>
{% endfor %}
{% else %}<h2>No problems found</h2><p>Nothing in this capture looks like a fault or an attack.</p>{% endif %}
<footer>Generated by {{ r.tool }} &middot; analysed offline in {{ r.analysis_seconds }} s &middot; no data left this machine.</footer>
</div></body></html>"""

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
_template = _env.from_string(_TEMPLATE)


def render_html(report_dict: dict) -> str:
    return _template.render(r=report_dict)
