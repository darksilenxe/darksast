import { h } from 'vue';

// Express session misconfiguration
session({
  secret: 'default-key',
  resave: true,
  saveUninitialized: true
});

// Angular-like sanitizer bypass pattern
const sanitizer = {
  bypassSecurityTrustHtml(value) {
    return value;
  }
};
const html = "<img src=x onerror=alert(1)>";
const trusted = sanitizer.bypassSecurityTrustHtml(html);
console.log(trusted);

// Vue render-function innerHTML sink pattern
const vnode = h('div', { innerHTML: html });
console.log(vnode);

// Next.js config-style dangerous SVG setting pattern
const nextConfig = {
  images: {
    dangerouslyAllowSVG: true
  }
};
console.log(nextConfig);
