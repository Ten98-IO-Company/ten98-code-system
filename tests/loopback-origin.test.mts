import assert from 'node:assert/strict';
import test from 'node:test';
import { appOrigin, oidcEndpoint } from '../index.mjs';

test("oidcEndpoint allowHttp 'loopback' admits plain http only on localhost, 127.0.0.1 and [::1]", () => {
  for (const raw of ['http://localhost:8080/realms/x', 'http://127.0.0.1:9000/', 'http://[::1]:5556/dex']) {
    assert.equal(oidcEndpoint(raw, { allowHttp: 'loopback', issuer: true }).href, new URL(raw).href);
  }
  for (const raw of ['http://idp.example.com/', 'http://127.0.0.2/', 'http://localhost.example.com/', 'http://10.0.0.1/', 'http://[::2]/']) {
    assert.throws(() => oidcEndpoint(raw, { allowHttp: 'loopback' }), TypeError, raw);
  }
  // The existing options keep their meaning.
  assert.throws(() => oidcEndpoint('http://localhost/'), TypeError);
  assert.equal(oidcEndpoint('http://idp.example.com/', { allowHttp: true }).hostname, 'idp.example.com');
  assert.throws(() => oidcEndpoint('http://localhost/#x', { allowHttp: 'loopback' }), TypeError);
  assert.throws(() => oidcEndpoint('http://u:p@localhost/', { allowHttp: 'loopback' }), TypeError);
  assert.throws(() => oidcEndpoint('https://idp.example.com/', { allowHttp: 'yes' as unknown as boolean }), TypeError);
});

test('appOrigin returns the origin of an https URL, or http on loopback', () => {
  assert.equal(appOrigin('https://campaign.ten98.io'), 'https://campaign.ten98.io');
  assert.equal(appOrigin('https://campaign.ten98.io/'), 'https://campaign.ten98.io');
  assert.equal(appOrigin('https://Campaign.Ten98.io:8443'), 'https://campaign.ten98.io:8443');
  for (const raw of ['http://localhost:3000', 'http://127.0.0.1:3018/', 'http://[::1]:3000']) assert.equal(appOrigin(raw), new URL(raw).origin);
});

test('appOrigin refuses non-origins, credentials and public plain http with APP_URL_INVALID', () => {
  for (const raw of [
    'http://campaign.ten98.io', 'http://127.0.0.2:3000', 'ftp://campaign.ten98.io', 'https://u:p@campaign.ten98.io',
    'https://campaign.ten98.io/app', 'https://campaign.ten98.io/?x=1', 'https://campaign.ten98.io/#', 'https://campaign.ten98.io//',
    'campaign.ten98.io', '',
  ]) assert.throws(() => appOrigin(raw), (error: unknown) => (error as { code?: string }).code === 'APP_URL_INVALID', raw);
});
