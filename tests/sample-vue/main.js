import { createApp } from 'vue';

// Express session misconfiguration
session({
  secret: 'my-secret',
  resave: true,
  saveUninitialized: true
});

const payload = { role: 'viewer' };
const state = { ...payload, active: true };

function applyKey(target, key, value) {
  target[key] = value;
  return target;
}

console.log(state, applyKey({}, 'safe', true));

createApp({
  template: '<h1>Sample Vue App</h1>'
}).mount('#app');
