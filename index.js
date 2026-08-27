import dotenv from 'dotenv';
import path from 'node:path';
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import forge from 'node-forge';

dotenv.config({ path: [ '.env.local', '.env' ], quiet: true });

const SRV_PORT = Number(process.env.SRV_PORT);
const TXT_FILE = path.resolve(import.meta.dirname, process.env.TXT_FILE);

console.log(`using file ${TXT_FILE}`);

function getText() {
  return fs.readFileSync(TXT_FILE, 'utf8').trim();
}

function mkTLS(text) {
  let i = 0;

  const keys = forge.pki.rsa.generateKeyPair({
    bits: 2048,
    prng: {
      getBytesSync(length) {
        let bytes = '';

        while (bytes.length < length) {
          bytes += crypto.createHash('sha256').update(text + i++).digest('latin1');
        }

        return bytes.slice(0, length);
      }
    }
  });

  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date('1970-01-01T00:00:00Z');
  cert.validity.notAfter = new Date('9999-12-31T23:59:59Z');
  cert.setSubject([ { name: 'commonName', value: text } ]);
  cert.setIssuer(cert.subject.attributes);
  cert.setExtensions([ {
    name: 'subjectAltName',
    altNames: [
      { type: 2, value: 'localhost' },
      { type: 7, ip: '127.0.0.1' }
    ]
  } ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    key: forge.pki.privateKeyToPem(keys.privateKey),
    cert: forge.pki.certificateToPem(cert)
  };
}

function mkHash(tls) {
  return new crypto.X509Certificate(tls.cert).fingerprint256.replaceAll(':', '');
}

let txt = getText();
let tls = mkTLS(txt);
let hash = mkHash(tls);
let timeout;

const server = https.createServer(tls, (req, res) => {
  res.end(hash);
}).listen(SRV_PORT, () => {
  const listen = server.address();
  let addr = listen.address;

  if (listen.family.toLowerCase() === 'ipv6') {
    addr = `[${addr}]`;
  }

  console.log(`listening on https://${addr}:${listen.port}`);
});

fs.watch(TXT_FILE, () => {
  clearTimeout(timeout);
  timeout = setTimeout(() => {
    const read = getText();
    if (read != txt) {
      txt = read;
      tls = mkTLS(txt);
      hash = mkHash(tls);
      server.setSecureContext(tls);
    }
  }, 100);
});
