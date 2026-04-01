import fs from 'fs';
import http from 'http';
import https from 'https';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import Handlebars from 'handlebars';
import yaml from 'js-yaml';
import vm from 'vm';
import shelljs from 'shelljs';
import cors from 'cors';
import React from 'react';

const req = { query: { url: 'http://evil.local' }, body: { path: '../../etc/passwd' } };
const res = {
  redirect(value) { return value; },
  sendFile(value) { return value; }
};
const db = { query(value) { return value; } };
const users = { find(value) { return value; } };
const userInput = req.query.url;
const token = 'header.payload.signature';
const secret = process.env.JWT_SECRET || 'changeme';
const apiKey = 'AKIA_TEST_SECRET';
const sanitizer = {
  bypassSecurityTrustUrl(value) { return value; },
  bypassSecurityTrustResourceUrl(value) { return value; }
};

fetch(userInput);
axios.get(userInput);
http.request(userInput);
https.get(userInput);
fs.readFileSync(req.body.path);
res.sendFile(req.body.path);
res.redirect(userInput);
window.location.href = userInput;
jwt.decode(token);
jwt.verify(token, secret, { algorithms: ['none'] });
crypto.createHash('md5');
const sessionId = Math.random().toString(36);
const resetToken = Math.random().toString(36).slice(2);
const csrfToken = 'csrf_' + Math.random().toString(36);
let accessToken;
accessToken = 'bearer_' + Math.random().toString(36);
const spinnerDelayMs = 300 + Math.floor(Math.random() * 200);
db.query('SELECT * FROM users WHERE id = ' + userInput);
users.find({ '$where': userInput, username: { '$regex': userInput } });
Handlebars.compile(userInput);
yaml.load(userInput);
vm.runInNewContext(userInput);
cors({ origin: '*', credentials: true });
shelljs.exec(userInput);
execa(userInput);
const safeUrl = sanitizer.bypassSecurityTrustUrl(userInput);
const resourceUrl = sanitizer.bypassSecurityTrustResourceUrl(userInput);
console.log(safeUrl, resourceUrl, apiKey, sessionId);

const nextConfig = {
  images: {
    remotePatterns: [
      { hostname: '*' }
    ]
  }
};

const sessionConfig = {
  cookie: {
    secure: false,
    httpOnly: false
  }
};

const insecureTlsOptions = {
  rejectUnauthorized: false
};

const serialize = {
  unserialize(value) { return value; },
  deserialize(value) { return value; }
};

const expressSessionConfig = {
  secret,
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false, sameSite: 'none' }
};

// Direct session() calls that should trigger the new refined rules
session({
  secret,
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false }
});

jwt.verify(token, secret, { ignoreExpiration: true });
window.open(userInput, '_blank');
res.cookie('sid', token, { secure: false, httpOnly: true });
db.query(`SELECT * FROM users WHERE id = '${userInput}'`);
serialize.unserialize(userInput);
serialize.deserialize(userInput);

console.log(nextConfig, sessionConfig, insecureTlsOptions, expressSessionConfig);

export function DangerousLink() {
  return <a href={userInput}>Open</a>;
}
