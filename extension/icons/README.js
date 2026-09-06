/**
 * PhishShield TR - Extension Icon Placeholder
 * 
 * Bu dosya icon placeholder'idir.
 * Gercek iconlar olusturmak icin:
 * 
 * 1. 16x16, 48x48, 128x128 PNG iconlar olusturun
 * 2. Dosyalari icons/ klasorune kaydedin:
 *    - icon16.png
 *    - icon48.png
 *    - icon128.png
 * 
 * Icon olusturma tavsiyeleri:
 * - Shield formunda
 * - Yesil (#4CAF50) guvenli, Kirmizi (#F44336) tehlikeli
 * - Turkuaz (#00d4ff) ana renk
 */

const ICON_SVG = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <defs>
    <linearGradient id="shield-grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#00d4ff"/>
      <stop offset="100%" style="stop-color:#00ff88"/>
    </linearGradient>
  </defs>
  <path d="M64 4 L12 24 L12 56 C12 88 36 116 64 124 C92 116 116 88 116 56 L116 24 Z" 
        fill="url(#shield-grad)" stroke="#fff" stroke-width="2"/>
  <text x="64" y="78" text-anchor="middle" font-size="48" fill="#fff">🛡️</text>
</svg>
`;

// Not: PNG olusturmak icin SVG'yi PNG'ye donusturmeniz gerekir
// Or: https://cloudconvert.com/svg-to-png
