import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import vm from 'node:vm';

function event() {
  const listeners = new Set();
  return {addListener: fn => listeners.add(fn), removeListener: fn => listeners.delete(fn),
    emit: (...args) => { for (const fn of [...listeners]) fn(...args); }, listeners};
}
async function setup(onPost) {
  const ports = [], timers = new Map(), intervals = [];
  let timerId = 0;
  const storage = {};
  const chrome = {
    runtime: {id: 'test-extension', onInstalled: event(), onStartup: event(), onMessage: event(),
      connectNative: () => {
        const port = {onMessage: event(), onDisconnect: event(), sent: [], disconnected: false,
          disconnect() { this.disconnected = true; },
          postMessage(message) { this.sent.push(message); onPost?.(this, message, ports.length); }};
        ports.push(port); return port;
      }},
    tabs: {onRemoved: event()},
    storage: {session: {
      get: async key => key == null ? {...storage} : {[key]: storage[key]},
      set: async values => Object.assign(storage, values),
      remove: async keys => { for (const key of Array.isArray(keys) ? keys : [keys]) delete storage[key]; },
    }},
  };
  const context = vm.createContext({chrome, crypto: {randomUUID}, URL, console,
    setTimeout: fn => { const id = ++timerId; timers.set(id, fn); return id; },
    clearTimeout: id => timers.delete(id), setInterval: fn => { intervals.push(fn); return intervals.length; }});
  const source = await readFile(new URL('../apps/chrome-extension/background.js', import.meta.url), 'utf8');
  const module = new vm.SourceTextModule(source + '\nexport {sendNative, sendNativeOnce, inflight};', {context});
  await module.link(specifier => {
    const names = specifier.includes('fill_flow') ? ['runFillLoginOnTab','runFillOtpFromVaultOnTab','runOtpFillOnTab','requestPageContext'] :
      ['handlePasskey','cancelPasskey','passkeySiteState','setPasskeySiteState','syncPasskeyScripts'];
    return new vm.SyntheticModule(names, function() { for (const name of names) this.setExport(name, () => {}); }, {context});
  });
  await module.evaluate();
  return {api: module.namespace, ports, timers, intervals, chrome,
    timeout() { const [id, fn] = timers.entries().next().value; timers.delete(id); fn(); }};
}
async function settle() { for (let i = 0; i < 20; i++) await Promise.resolve(); }
function respond(port, payload = {ok: true}) {
  port.onMessage.emit({...payload, request_id: port.sent.at(-1).request_id});
}

test('a timed-out read reconnects once and late disconnect cannot erase the new connection', async () => {
  const h = await setup();
  const pending = h.api.sendNative({action: 'status'});
  await settle();
  const old = h.ports[0]; h.timeout(); await settle();
  assert.equal(h.ports.length, 2);
  old.onDisconnect.emit();
  assert.equal(h.api.inflight.size, 1);
  respond(h.ports[1]);
  assert.equal((await pending).ok, true);
  assert.equal(h.api.inflight.size, 0);
});

test('a response arriving during postMessage is not lost', async () => {
  const h = await setup((port, message) => port.onMessage.emit({ok: true, request_id: message.request_id}));
  assert.equal((await h.api.sendNative({action: 'status'})).ok, true);
  assert.equal(h.timers.size, 0);
});

test('disconnection never replays a password save', async () => {
  const h = await setup();
  const pending = h.api.sendNative({action: 'credential.save', password: 'synthetic-test-secret'});
  const rejection = assert.rejects(pending, /disconnected/);
  await settle(); h.ports[0].onDisconnect.emit(); await rejection;
  assert.equal(h.ports.length, 1);
  assert.equal(h.api.inflight.size, 0);
  assert.equal(h.timers.size, 0);
});

test('timed-out signing request is not replayed', async () => {
  const h = await setup();
  const pending = h.api.sendNative({action: 'passkey.begin'});
  const rejection = assert.rejects(pending, /超时/);
  await settle(); h.timeout(); await rejection;
  assert.equal(h.ports.length, 1);
  assert.equal(h.ports[0].disconnected, true);
});

test('postMessage failure releases all listeners and pending state', async () => {
  const h = await setup(() => { throw new Error('port closed'); });
  await assert.rejects(h.api.sendNativeOnce({action: 'credential.update'}), /断开/);
  assert.equal(h.api.inflight.size, 0);
  assert.equal(h.timers.size, 0);
  assert.equal(h.ports[0].onMessage.listeners.size, 0);
});

test('structured agent timeout retries only a read, and retry count is bounded', async () => {
  const h = await setup((port, message) => queueMicrotask(() => port.onMessage.emit({ok: false, code: 'agent_timeout', request_id: message.request_id})));
  const response = await h.api.sendNative({action: 'status'});
  assert.equal(response.code, 'agent_timeout');
  assert.equal(h.ports.length, 2);
  const write = await h.api.sendNative({action: 'credential.update'});
  assert.equal(write.code, 'agent_timeout');
  assert.equal(h.ports.length, 2);
});

test('authorization rejection is returned without automatic retry', async () => {
  const h = await setup((port, message) => queueMicrotask(() => port.onMessage.emit({ok: false, code: 'peer_denied', request_id: message.request_id})));
  assert.equal((await h.api.sendNative({action: 'status'})).code, 'peer_denied');
  assert.equal(h.ports.length, 1);
  assert.equal(h.ports[0].disconnected, true);
});

test('an outdated host is replaced for reads, while writes are never replayed', async () => {
  const h = await setup((port, message, number) => queueMicrotask(() => port.onMessage.emit({
    ok: number > 1, ...(number === 1 ? {code: 'host_outdated'} : {}), request_id: message.request_id,
  })));
  assert.equal((await h.api.sendNative({action: 'status'})).ok, true);
  assert.equal(h.ports.length, 2);
  const write = await setup((port, message) => queueMicrotask(() => port.onMessage.emit({
    ok: false, code: 'host_outdated', request_id: message.request_id,
  })));
  assert.equal((await write.api.sendNative({action: 'credential.save'})).code, 'host_outdated');
  assert.equal(write.ports.length, 1);
});
