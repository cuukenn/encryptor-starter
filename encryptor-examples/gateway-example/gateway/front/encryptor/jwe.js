'use strict';
/**
 * JWE 客户端（WebCrypto）—— 与 encryptor-starter v2 协议同构。
 *
 * <p>协议要点：请求 {@code alg=RSA-OAEP-256}（RSA 公钥）或 {@code alg=ECDH-ES}（P-256 公钥，
 * 直接密钥协商：临时密钥对 + Concat KDF，{@code epk} 随 header 走、{@code encrypted_key} 段为空）、
 * 内容一律 {@code enc=A256GCM}（可用 {@code opts.enc} 指定 A128/A192/A256GCM），protected header 携带
 * {@code uri/m/dir/ts/nonce} claims（AAD = protected header 的 ASCII 字节，RFC 7516）；
 * 响应 {@code alg=dir} 复用请求的 CEK，{@code enc} 以响应头为准。CEK/IV/nonce 每次请求重新生成
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
const ALG_ECDH = 'ECDH-ES';
const ENC = 'A256GCM';
/** 各 enc 的 CEK 字节数（与 JOSE 定义一致）。 */
const ENC_KEY_BYTES = {A128GCM: 16, A192GCM: 24, A256GCM: 32};
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

/** 是否走 ECDH-ES（P-256 直接密钥协商）：JWKS 里 alg=ECDH-ES 或 kty=EC/crv=P-256。 */
function isEcdhJwk(jwk) {
    if (!jwk) {
        return false;
    }
    if (jwk.kty === 'EC') {
        if (jwk.crv !== 'P-256') {
            throw new Error('unsupported EC curve: ' + jwk.crv);
        }
        return true;
    }
    return jwk.alg === ALG_ECDH;
}

/** JWK 里只保留导入所需成员（kid/alg/use 等附加成员在部分实现下会让 importKey 抛错）。 */
function importableJwk(jwk) {
    if (jwk.kty === 'RSA') {
        return {kty: 'RSA', n: jwk.n, e: jwk.e};
    }
    if (jwk.kty === 'EC') {
        return {kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y};
    }
    return jwk;
}

/** 4 字节大端整数（Concat KDF 的长度前缀 / 计数器都是它）。 */
function u32be(value) {
    return new Uint8Array([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

function concatBytes(...parts) {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

/**
 * Concat KDF（NIST SP 800-56A §5.8.1 / RFC 7518 §4.6.2）：K = SHA-256(counter=1 || Z || OtherInfo)，
 * OtherInfo = AlgorithmID(=enc) || PartyUInfo(空) || PartyVInfo(空) || SuppPubInfo(keydatalen)。
 *
 * @returns {Promise<Uint8Array>} 前 keyLengthBits/8 字节
 */
async function concatKdf(z, algorithmId, keyLengthBits) {
    const algorithm = new TextEncoder().encode(algorithmId);
    const otherInfo = concatBytes(u32be(algorithm.length), algorithm, u32be(0), u32be(0), u32be(keyLengthBits));
    const digest = new Uint8Array(await subtle.digest('SHA-256', concatBytes(u32be(1), z, otherInfo)));
    return digest.slice(0, keyLengthBits / 8);
}

/** RSA-OAEP-256：随机 CEK，用公钥封装。 */
async function wrapCekRsa(jwk, encName, cekBytes) {
    const cek = webcrypto.getRandomValues(new Uint8Array(cekBytes));
    const key = await subtle.importKey('jwk', importableJwk(jwk), {name: 'RSA-OAEP', hash: 'SHA-256'}, false,
        ['encrypt']);
    return {cek, alg: ALG, encryptedKey: new Uint8Array(await subtle.encrypt({name: 'RSA-OAEP'}, key, cek))};
}

/** ECDH-ES（直接密钥协商）：临时 P-256 私钥做 ECDH 得 Z，Concat KDF 派生 CEK，encrypted_key 段为空。 */
async function wrapCekEcdh(jwk, encName, cekBytes) {
    const serverKey = await subtle.importKey('jwk', importableJwk(jwk), {name: 'ECDH', namedCurve: 'P-256'},
        false, []);
    const ephemeral = await subtle.generateKey({name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveBits']);
    const z = new Uint8Array(await subtle.deriveBits({name: 'ECDH', public: serverKey}, ephemeral.privateKey,
        256));
    const cek = await concatKdf(z, encName, cekBytes * 8);
    const pub = await subtle.exportKey('jwk', ephemeral.publicKey);
    return {
        cek, alg: ALG_ECDH, epk: {kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y},
        encryptedKey: new Uint8Array(0)
    };
}

/**
 * 加密一个请求：生成新 CEK/IV/nonce，构造 RSA-OAEP-256 + A256GCM 的 JWE compact。
 *
 * @param plaintext 明文（JSON body / urlencoded 查询串）
 * @param opts {kid, publicKeyJwk, uri, method}
 * @returns {Promise<{jwe: string, cek: Uint8Array}>} cek 须由调用方保留——响应 alg=dir 复用它
 */
async function encrypt(plaintext, {kid, publicKeyJwk, uri, method, enc}) {
    const encryption = enc || ENC;
    const cekBytes = ENC_KEY_BYTES[encryption];
    if (!cekBytes) {
        throw new Error('unsupported enc: ' + encryption);
    }
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const nonce = b64urlEncode(webcrypto.getRandomValues(new Uint8Array(16)));
    // 按服务端公钥类型选封装方式：EC(P-256) → ECDH-ES 直接协商；否则 RSA-OAEP-256
    const wrapped = await (isEcdhJwk(publicKeyJwk) ? wrapCekEcdh : wrapCekRsa)(publicKeyJwk, encryption,
        cekBytes);
    const cek = wrapped.cek;
    const header = {
        alg: wrapped.alg, enc: encryption, kid, typ: 'encryptor+jwe',
        uri, m: method, dir: 'req', ts: Date.now(), nonce
    };
    if (wrapped.epk) {
        header.epk = wrapped.epk;
    }
    const protectedHeader = b64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
    // RFC 7516：compact 序列化的 AAD 就是 protected header 的 ASCII 字节
    const aad = Uint8Array.from(protectedHeader, ch => ch.charCodeAt(0));
    const aesKey = await subtle.importKey('raw', cek, {name: 'AES-GCM'}, false, ['encrypt']);
    const ctAndTag = new Uint8Array(await subtle.encrypt(
        {name: 'AES-GCM', iv, additionalData: aad, tagLength: TAG_BYTES * 8}, aesKey,
        new TextEncoder().encode(plaintext)));
    const ct = ctAndTag.slice(0, ctAndTag.length - TAG_BYTES);
    const tag = ctAndTag.slice(ctAndTag.length - TAG_BYTES);
    // ECDH-ES 的 encrypted_key 段为空（直接协商），compact 里该段就是空串
    const encryptedKey = wrapped.encryptedKey;
    const compact = [protectedHeader, b64urlEncode(encryptedKey), b64urlEncode(iv),
        b64urlEncode(ct), b64urlEncode(tag)].join('.');
    return {jwe: compact, cek, alg: wrapped.alg, enc: encryption};
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
    if (header.alg !== 'dir') {
        throw new Error('unsupported response jwe alg: ' + header.alg);
    }
    // enc 以响应头为准（服务端可能按配置用 A128/A192/A256GCM），不再写死 A256GCM
    const encBytes = ENC_KEY_BYTES[header.enc];
    if (!encBytes) {
        throw new Error('unsupported response enc: ' + header.enc);
    }
    if (cek.length !== encBytes) {
        throw new Error('cek length ' + cek.length + ' does not match enc ' + header.enc);
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
