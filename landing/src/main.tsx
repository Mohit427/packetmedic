import './fonts';
import './styles.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

/* Embedded in Streamlit via components.html (same-origin srcdoc iframe):
   grow the iframe to the page's full height so the parent page scrolls
   naturally, with no nested scrollbar. Harmless when opened standalone. */
function fitFrame() {
  try {
    const fe = window.frameElement as HTMLIFrameElement | null;
    if (!fe) return;
    const h = Math.ceil(document.documentElement.scrollHeight);
    if (Math.abs(fe.offsetHeight - h) > 2) {
      fe.style.height = `${h}px`;
      fe.setAttribute('height', String(h));
    }
  } catch {
    /* cross-origin parent: keep the fixed height */
  }
}
new ResizeObserver(fitFrame).observe(document.body);
window.addEventListener('load', fitFrame);
document.fonts?.ready.then(fitFrame);
