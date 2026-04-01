import React from 'react';

export function Profile({ html }) {
  return (
    <section>
      <h1>Profile</h1>
      <div dangerouslySetInnerHTML={{ __html: html }} />
    </section>
  );
}

// Express session misconfiguration
session({
  secret: 'default-secret',
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false }
});

const payload = { role: 'user' };
const merged = { ...payload, active: true };

export function applyKey(target, key, value) {
  target[key] = value;
  return target;
}

console.log(merged);
