// Self-hosted faces, latin subset, woff2 only. Vite inlines them into the single HTML file.
import bsd700 from '@fontsource/big-shoulders-display/files/big-shoulders-display-latin-700-normal.woff2';
import bsd800 from '@fontsource/big-shoulders-display/files/big-shoulders-display-latin-800-normal.woff2';
import ah400 from '@fontsource/atkinson-hyperlegible/files/atkinson-hyperlegible-latin-400-normal.woff2';
import ah700 from '@fontsource/atkinson-hyperlegible/files/atkinson-hyperlegible-latin-700-normal.woff2';
import jb400 from '@fontsource/jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff2';
import jb600 from '@fontsource/jetbrains-mono/files/jetbrains-mono-latin-600-normal.woff2';
import pm400 from '@fontsource/permanent-marker/files/permanent-marker-latin-400-normal.woff2';

const faces: [string, string, number][] = [
  ['Big Shoulders Display', bsd700, 700], ['Big Shoulders Display', bsd800, 800],
  ['Atkinson Hyperlegible', ah400, 400], ['Atkinson Hyperlegible', ah700, 700],
  ['JetBrains Mono', jb400, 400], ['JetBrains Mono', jb600, 600],
  ['Permanent Marker', pm400, 400],
];

const css = faces
  .map(([f, src, w]) => `@font-face{font-family:'${f}';src:url(${src}) format('woff2');font-weight:${w};font-style:normal;font-display:swap}`)
  .join('\n');
const tag = document.createElement('style');
tag.textContent = css;
document.head.appendChild(tag);
