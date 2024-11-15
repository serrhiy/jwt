'use strict';

const path = require('node:path');
const http2 = require('node:http2');
const fsp = require('node:fs/promises');

const certpath = path.join(__dirname, '../cert/cert.pem');
const keypath = path.join(__dirname, '../cert/key.pem');

const port = 8000;

const tlsOptions = async (keypath, certpath) => ({
  key: await fsp.readFile(keypath),
  cert: await fsp.readFile(certpath),
});

const createUnsecureJWT = (data) => {
  const header = JSON.stringify({ alg: 'none' });
  const payload = JSON.stringify(data);
  const headerBuffer = Buffer.from(header, 'utf-8').toString('base64url');
  const payloadBuffer = Buffer.from(payload, 'utf-8').toString('base64url');
  return headerBuffer + '.' + payloadBuffer + '.';
};

const parseUnsecureJWT = (token) => {
  const index = token.indexOf('.');
  const payload = token.slice(index + 1, token.length - 1);
  const string = Buffer.from(payload, 'base64url').toString('utf-8');
  return JSON.parse(string);
};

const data = {
  sub: '4673264782482',
  name: 'Antoninus Pius',
  admin: true
};

const parseCookies = (string = '') => {
  const result = {};
  const cookies = string.split(';');
  for (const cookie of cookies) {    
    const [key, value = ''] = cookie.split('=');    
    result[key.trim()] = value.trim();
  }
  return result;
};

const MAX_AGE = (30 * 24 * 60 * 60).toString();
const DEFAULT_COOKIE = `Max-Age=${MAX_AGE}; Path=/; Secure; HttpOnly`;

const main = async () => {
  const options = await tlsOptions(keypath, certpath);  
  const server = http2.createSecureServer(options);
  server.on('stream', (stream, headers) => {
    const cookie = parseCookies(headers.cookie);
    if ('token' in cookie) {
      const data = parseUnsecureJWT(cookie.token);
      console.log({ data, url: headers[':path'] });
      stream.respond({ ':status': 200 });
      return void stream.end('user');
    }
    const token = createUnsecureJWT(data);
    stream.respond({
      ':status': 200,
      'set-cookie': `token=${token}; ${DEFAULT_COOKIE}`
    });
    stream.end('some text');
  });
  server.listen(port);
};

main();
