'use strict';
/**
 * JWE 客户端（WebCrypto）—— 与 encryptor-starter v2 协议同构。
 *
 * <p>协议要点：请求 {@code alg=RSA-OAEP-256 + enc=A256GCM}，protected header 携带
 * {@code uri/m/dir/ts/nonce} claims（AAD = protected header 的 ASCII 字节，RFC 7516）；
 * 响应 {@code alg=dir} 复用请求的 CEK。CEK/IV/nonce 每次请求重新生成
 * （{@code crypto.getRandomValues}，禁止 Math.random）。</p>
 *
 * <p>Node ≥15 与浏览器双环境：浏览器直接用 {@code globalThis.crypto}，
 * Node 用 {@code require('crypto').webcrypto}。</p>
 *
 * @author changgg
 */
const webcrypto = (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle)
    ? globalThis.crypto
    : require('crypto').webcrypto;
const subtle = webcrypto.subtle;

const ALG = 'RSA-OAEP-256';
const ENC = 'A256GCM';
const TAG_BYTES = 16;

function b64urlEncode(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) {
        bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
        out[i] = bin.charCodeAt(i);
    }
    return out;
}

/** JWK 里只保留导入所需成员（kid/alg/use 等附加成员在部分实现下会让 importKey 抛错）。 */
function importableJwk(jwk) {
    if (jwk.kty === 'RSA') {
        return {kty: 'RSA', n: jwk.n, e: jwk.e};
    }
    return jwk;
}

/**
 * 加密一个请求：生成新 CEK/IV/nonce，构造 RSA-OAEP-256 + A256GCM 的 JWE compact。
 *
 * @param plaintext 明文（JSON body / urlencoded 查询串）
 * @param opts {kid, publicKeyJwk, uri, method}
 * @returns {Promise<{jwe: string, cek: Uint8Array}>} cek 须由调用方保留——响应 alg=dir 复用它
 */
async function encrypt(plaintext, {kid, publicKeyJwk, uri, method}) {
    const cek = webcrypto.getRandomValues(new Uint8Array(32));
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const nonce = b64urlEncode(webcrypto.getRandomValues(new Uint8Array(16)));
    const header = {
        alg: ALG, enc: ENC, kid, typ: 'encryptor+jwe',
        uri, m: method, dir: 'req', ts: Date.now(), nonce
    };
    const protectedHeader = b64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
    // RFC 7516：compact 序列化的 AAD 就是 protected header 的 ASCII 字节
    const aad = Uint8Array.from(protectedHeader, ch => ch.charCodeAt(0));
    const aesKey = await subtle.importKey('raw', cek, {name: 'AES-GCM'}, false, ['encrypt']);
    const ctAndTag = new Uint8Array(await subtle.encrypt(
        {name: 'AES-GCM', iv, additionalData: aad, tagLength: TAG_BYTES * 8}, aesKey,
        new TextEncoder().encode(plaintext)));
    const ct = ctAndTag.slice(0, ctAndTag.length - TAG_BYTES);
    const tag = ctAndTag.slice(ctAndTag.length - TAG_BYTES);
    const rsaKey = await subtle.importKey('jwk', importableJwk(publicKeyJwk),
        {name: 'RSA-OAEP', hash: 'SHA-256'}, false, ['encrypt']);
    const encryptedKey = new Uint8Array(await subtle.encrypt({name: 'RSA-OAEP'}, rsaKey, cek));
    const compact = [protectedHeader, b64urlEncode(encryptedKey), b64urlEncode(iv),
        b64urlEncode(ct), b64urlEncode(tag)].join('.');
    return {jwe: compact, cek};
}

/**
 * 解密服务端响应（alg=dir，复用请求 CEK）。
 *
 * @param jwe JWE compact
 * @param cek encrypt() 返回的 CEK
 * @returns {Promise<string>} 明文
 */
async function decrypt(jwe, cek) {
    const [h, , ivS, ctS, tagS] = jwe.split('.');
    const header = JSON.parse(new TextDecoder().decode(b64urlDecode(h)));
    if (header.alg !== 'dir' || header.enc !== ENC) {
        throw new Error('unsupported response jwe: ' + header.alg + '/' + header.enc);
    }
    const aad = Uint8Array.from(h, ch => ch.charCodeAt(0));
    const ct = b64urlDecode(ctS);
    const tag = b64urlDecode(tagS);
    const ctAndTag = new Uint8Array(ct.length + tag.length);
    ctAndTag.set(ct);
    ctAndTag.set(tag, ct.length);
    const aesKey = await subtle.importKey('raw', cek, {name: 'AES-GCM'}, false, ['decrypt']);
    const pt = await subtle.decrypt(
        {name: 'AES-GCM', iv: b64urlDecode(ivS), additionalData: aad, tagLength: TAG_BYTES * 8},
        aesKey, ctAndTag);
    return new TextDecoder().decode(pt);
}

/** 进程内 JWKS 缓存：{byKid: Map<kid, jwk>, activeKid}。 */
let keyCache = null;

/**
 * 拉取（并缓存）JWKS。
 *
 * @param url 端点，如 http://127.0.0.1:8081/.well-known/encryptor-keys
 * @param force true 时忽略缓存强制刷新（收到 400 后刷新重试用）
 */
async function fetchKeys(url, force) {
    if (keyCache && !force) {
        return keyCache;
    }
    // 惰性加载：浏览器环境没有 axios，用全局 fetch；Node 用 axios
    let data;
    if (typeof fetch === 'function') {
        data = await (await fetch(url)).json();
    } else {
        data = (await require('axios').get(url)).data;
    }
    const byKid = new Map();
    for (const jwk of (data.keys || [])) {
        byKid.set(jwk.kid, jwk);
    }
    keyCache = {byKid, activeKid: data.activeKid};
    return keyCache;
}

module.exports = {encrypt, decrypt, fetchKeys};
