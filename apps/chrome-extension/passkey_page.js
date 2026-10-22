// 网页世界只接触 WebAuthn 公共参数和响应；私钥生成与签名均在 App 内完成。
(() => {
  if (!window.isSecureContext || window !== window.top || !navigator.credentials || !window.PublicKeyCredential) return;
  const container = navigator.credentials;
  const originalCreate = container.create.bind(container);
  const originalGet = container.get.bind(container);
  const channel = "credpivot.passkey.v1";

  function encode(value) {
    const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) :
      ArrayBuffer.isView(value) ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength) : null;
    if (!bytes || !bytes.length || bytes.length > 4096) throw new TypeError("Invalid WebAuthn BufferSource");
    let text = "";
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  }

  function decode(value) {
    const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
    const text = atob(normalized);
    return Uint8Array.from(text, (c) => c.charCodeAt(0)).buffer;
  }

  function serialize(pk, create) {
    const result = { challenge: encode(pk.challenge) };
    for (const field of ["rpId", "rp", "timeout", "pubKeyCredParams", "authenticatorSelection", "userVerification", "attestation", "extensions", "hints"]) {
      if (pk[field] !== undefined) result[field] = pk[field];
    }
    if (create) result.user = { id: encode(pk.user.id), name: pk.user.name, displayName: pk.user.displayName };
    for (const field of ["excludeCredentials", "allowCredentials"]) {
      if (pk[field] !== undefined) result[field] = Array.from(pk[field], (d) => ({ type: d.type, id: encode(d.id), transports: d.transports }));
    }
    // 不传页面对象/访问器到扩展，也不传 AbortSignal 等无法序列化的字段。
    const serialized = JSON.stringify(result);
    if (serialized.length > 64 * 1024) throw new TypeError("WebAuthn options too large");
    return JSON.parse(serialized);
  }

  function credential(data, create) {
    const fields = data.response;
    const response = Object.create((create ? AuthenticatorAttestationResponse : AuthenticatorAssertionResponse).prototype);
    for (const field of ["clientDataJSON", "attestationObject", "authenticatorData", "signature", "userHandle"]) {
      if (fields[field] !== undefined) Object.defineProperty(response, field, {value: fields[field] === null ? null : decode(fields[field]), enumerable: true});
    }
    if (create) {
      Object.defineProperties(response, {
        getTransports: {value: () => [...fields.transports]},
        getAuthenticatorData: {value: () => decode(fields.authenticatorData)},
        getPublicKey: {value: () => decode(fields.publicKey)},
        getPublicKeyAlgorithm: {value: () => fields.publicKeyAlgorithm},
      });
    }
    const value = Object.create(PublicKeyCredential.prototype);
    Object.defineProperties(value, {
      id: {value: data.id, enumerable: true}, rawId: {value: decode(data.rawId), enumerable: true},
      type: {value: "public-key", enumerable: true}, response: {value: response, enumerable: true},
      authenticatorAttachment: {value: data.authenticatorAttachment, enumerable: true},
      getClientExtensionResults: {value: () => structuredClone(data.clientExtensionResults)},
      toJSON: {value: () => structuredClone(data)},
    });
    return value;
  }

  async function request(options, create) {
    const original = create ? originalCreate : originalGet;
    // 自动填充条件请求暂交浏览器处理，不抢占其已有凭据提供器。
    if (!options?.publicKey || ["conditional", "silent"].includes(options.mediation)) return original(options);
    if (options.signal?.aborted) throw new DOMException("WebAuthn request aborted", "AbortError");
    let publicKey;
    try { publicKey = serialize(options.publicKey, create); }
    catch (_) { return original(options); }
    const reply = await new Promise((resolve, reject) => {
      const ports = new MessageChannel();
      let finished = false;
      const requested = Number(options.publicKey.timeout);
      const timeout = Number.isFinite(requested) && requested > 0 ? Math.min(120_000, requested) : 120_000;
      let timer;
      const cleanup = () => {
        clearTimeout(timer);
        options.signal?.removeEventListener("abort", abort);
        ports.port1.close();
      };
      const abort = () => {
        if (finished) return;
        finished = true;
        ports.port1.postMessage({cancel: true});
        cleanup();
        reject(new DOMException("WebAuthn request aborted or timed out", options.signal?.aborted ? "AbortError" : "NotAllowedError"));
      };
      timer = setTimeout(abort, timeout);
      options.signal?.addEventListener("abort", abort, {once: true});
      ports.port1.onmessage = (event) => {
        if (finished) return;
        finished = true;
        cleanup();
        resolve(event.data);
      };
      window.postMessage({channel, kind: create ? "create" : "get", options: publicKey}, location.origin, [ports.port2]);
    });
    if (options.signal?.aborted) throw new DOMException("WebAuthn request aborted", "AbortError");
    if (reply?.fallback) return original(options);
    if (reply?.error) throw new DOMException(reply.error.message || "Passkey request failed", reply.error.name || "NotAllowedError");
    if (!reply?.credential) throw new DOMException("Invalid passkey response", "UnknownError");
    return credential(reply.credential, create);
  }

  Object.defineProperties(container, {
    create: {configurable: true, writable: true, value: (options) => request(options, true)},
    get: {configurable: true, writable: true, value: (options) => request(options, false)},
  });
})();
