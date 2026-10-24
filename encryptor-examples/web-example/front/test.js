'use strict';
/**
 * 端到端断言脚本：JWKS / GET / POST(json) / POST(form) / ECDH-ES / 篡改 / QUERY 共存与载体判定 八组，全过 exit 0，任一失败 exit 1。
 * 需先启动 web-example（8081）。跑法：node front/test.js
 *
 * @author changgg
 */
const jwe = require('./encryptor/jwe')
const axios = require('axios');
const qs = require('qs');

const BASE = 'http://127.0.0.1:8081';
const JWKS_URL = BASE + '/.well-known/encryptor-keys';

let failed = 0;

function check(name, ok, detail) {
    if (ok) {
        console.log('PASS ' + name);
    } else {
        failed++;
        console.error('FAIL ' + name + (detail ? ' — ' + detail : ''));
    }
}

function currentKey(keys) {
    return {kid: keys.activeKid, publicKeyJwk: keys.byKid.get(keys.activeKid)};
}

async function main() {
    // 1. JWKS：activeKid 可解析出 jwk，且不含私钥成员 d
    const keys = await jwe.fetchKeys(JWKS_URL);
    const jwk = keys.byKid.get(keys.activeKid);
    check('jwks: activeKid 有对应 jwk', !!jwk, 'activeKid=' + keys.activeKid);
    check('jwks: jwk 不含私钥 d', !jwk || !('d' in jwk));

    // 2. GET
    {
        const {jwe: compact, cek} = await jwe.encrypt(qs.stringify({name: '1'}),
            {...currentKey(keys), uri: '/test/hello', method: 'GET'});
        const res = await axios.get(BASE + '/test/hello', {params: {jwe: compact}});
        const plain = await jwe.decrypt(res?.data?.jwe, cek);
        check('get: 200 且解回明文含 Hello, 1（服务端回显）', plain.includes('Hello, 1'), plain);
    }

    // 3. POST json
    {
        const {jwe: compact, cek} = await jwe.encrypt(JSON.stringify({name: '1'}),
            {...currentKey(keys), uri: '/test/hello', method: 'POST'});
        const res = await axios.post(BASE + '/test/hello', {jwe: compact},
            {headers: {'Content-Type': 'application/json'}});
        const plain = await jwe.decrypt(res?.data?.jwe, cek);
        check('post-json: 200 且解回明文含 name', plain.includes('name'), plain);
    }

    // 4. POST form
    {
        const {jwe: compact, cek} = await jwe.encrypt(qs.stringify({name: '1'}),
            {...currentKey(keys), uri: '/test/hello', method: 'POST'});
        const res = await axios.post(BASE + '/test/hello', qs.stringify({jwe: compact}),
            {headers: {'Content-Type': 'application/x-www-form-urlencoded'}});
        const plain = await jwe.decrypt(res?.data?.jwe, cek);
        check('post-form: 200 且解回明文含 name=[1]（表单被解析）', plain.includes('name=[1]'), plain);
    }

    // 5. ECDH-ES（P-256 直接密钥协商）：/test/ec 只接受 ec-2026
    {
        const ecKey = keys.byKid.get('ec-2026');
        check('jwks: ec-2026 是 kty=EC/crv=P-256', !!ecKey && ecKey.kty === 'EC' && ecKey.crv === 'P-256',
            JSON.stringify(ecKey));
        const {jwe: compact, cek, alg} = await jwe.encrypt(qs.stringify({name: 'ec'}),
            {kid: 'ec-2026', publicKeyJwk: ecKey, uri: '/test/ec', method: 'GET'});
        check('ecdh-es: alg=ECDH-ES 且 encrypted_key 段为空', alg === 'ECDH-ES' && compact.split('.')[1] === '',
            'alg=' + alg + ' seg=' + compact.split('.')[1]);
        const res = await axios.get(BASE + '/test/ec', {params: {jwe: compact}});
        const plain = await jwe.decrypt(res?.data?.jwe, cek);
        check('ecdh-es: 200 且解回明文含 EC, ec', plain.includes('EC, ec'), plain);
    }

    // 6. ECDH-ES 反向：/test/ec 拒绝 RSA kid（uri 级 kid 白名单）
    {
        const {jwe: compact} = await jwe.encrypt(qs.stringify({name: '1'}),
            {...currentKey(keys), uri: '/test/ec', method: 'GET'});
        try {
            await axios.get(BASE + '/test/ec', {params: {jwe: compact}});
            check('ecdh-es: RSA kid 打 /test/ec 必须非 200', false);
        } catch (err) {
            check('ecdh-es: RSA kid 打 /test/ec 必须 400', err?.response?.status === 400,
                'status=' + err?.response?.status);
        }
    }

    // 7. 未在白名单的 enc 必须被拒（fail-closed）
    {
        const ecKey = keys.byKid.get('ec-2026');
        const {jwe: compact} = await jwe.encrypt(qs.stringify({name: 'ec'}),
            {kid: 'ec-2026', publicKeyJwk: ecKey, uri: '/test/ec', method: 'GET', enc: 'A128GCM'});
        try {
            await axios.get(BASE + '/test/ec', {params: {jwe: compact}});
            check('ecdh-es: A128GCM 未在白名单必须非 200', false);
        } catch (err) {
            check('ecdh-es: A128GCM 未在白名单必须 400', err?.response?.status === 400,
                'status=' + err?.response?.status);
        }
    }

    // 8. 篡改任一字节必须 400（防篡改可执行断言）
    {
        const {jwe: compact} = await jwe.encrypt(qs.stringify({name: '1'}),
            {...currentKey(keys), uri: '/test/hello', method: 'GET'});
        const parts = compact.split('.');
        const iv = Buffer.from(parts[2], 'base64url');
        iv[0] ^= 0xff;
        parts[2] = iv.toString('base64url');
        try {
            await axios.get(BASE + '/test/hello', {params: {jwe: parts.join('.')}});
            check('tamper: 篡改 iv 后必须非 200', false);
        } catch (err) {
            check('tamper: 篡改 iv 后必须 400', err?.response?.status === 400,
                'status=' + err?.response?.status);
        }
    }

    // 8. QUERY 载体共存与判定（2026-10 契约：明文即完整 query；jwe 在 query 上一律按 QUERY）
    {
        // 8a. 原始 query 参数与 jwe 共存：明文为准，raw 参数被丢弃（与网关同口径）
        const {jwe: compact, cek} = await jwe.encrypt(qs.stringify({name: 'CLEAN'}),
            {...currentKey(keys), uri: '/test/hello', method: 'GET'});
        const res = await axios.get(BASE + '/test/hello', {params: {name: 'RAW', jwe: compact}});
        const plain = await jwe.decrypt(res?.data?.jwe, cek);
        check('query 共存: 原始 name=RAW 被明文 name=CLEAN 取代（明文为准）',
            plain.includes('Hello, CLEAN') && !plain.includes('RAW'), plain);
    }
    {
        // 8b. form content-type + jwe 同时在 query 与 form body：query 胜出（QUERY 载体），
        //     参数视图来自 query 明文，form body 原样透传给下游
        const q = await jwe.encrypt(qs.stringify({name: 'FROM_QUERY'}),
            {...currentKey(keys), uri: '/test/hello', method: 'POST'});
        const f = await jwe.encrypt(qs.stringify({name: 'FROM_FORM'}),
            {...currentKey(keys), uri: '/test/hello', method: 'POST'});
        const res = await axios.post(BASE + '/test/hello?jwe=' + encodeURIComponent(q.jwe),
            qs.stringify({jwe: f.jwe}),
            {headers: {'Content-Type': 'application/x-www-form-urlencoded'}});
        const plain = await jwe.decrypt(res?.data?.jwe, q.cek);
        check('query+form 共存: query jwe 胜出且 form body 原样透传',
            plain.includes('FROM_QUERY') && plain.includes('jwe') && !plain.includes('FROM_FORM'), plain);
    }

    process.exitCode = failed === 0 ? 0 : 1;
}

main().catch(err => {
    console.error(err?.response?.status, err?.response?.data || err?.message);
    process.exitCode = 1;
});
