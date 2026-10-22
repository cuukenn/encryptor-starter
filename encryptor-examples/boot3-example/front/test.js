'use strict';
/**
 * 端到端断言脚本：GET / POST(json) / POST(form) / JWKS 四条，全过 exit 0，任一失败 exit 1。
 * 需先启动 gateway-example 网关（8080）。跑法：node front/test.js
 *
 * @author changgg
 */
const jwe = require('./encryptor/jwe')
const axios = require('axios');
const qs = require('qs');

const BASE = 'http://127.0.0.1:8080';
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
        check('get: 200 且解回明文含 Hello, 1（下游回显）', plain.includes('Hello, 1'), plain);
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

    // 5. ECDH-ES（P-256 直接密钥协商）：网关侧同样支持
    {
        const ecKey = keys.byKid.get('ec-gw-2026');
        check('jwks: ec-gw-2026 是 kty=EC/crv=P-256', !!ecKey && ecKey.kty === 'EC' && ecKey.crv === 'P-256',
            JSON.stringify(ecKey));
        const {jwe: compact, cek, alg} = await jwe.encrypt(qs.stringify({name: 'ec'}),
            {kid: 'ec-gw-2026', publicKeyJwk: ecKey, uri: '/test/hello', method: 'GET'});
        check('ecdh-es: alg=ECDH-ES 且 encrypted_key 段为空', alg === 'ECDH-ES' && compact.split('.')[1] === '',
            'alg=' + alg + ' seg=' + compact.split('.')[1]);
        const res = await axios.get(BASE + '/test/hello', {params: {jwe: compact}});
        const plain = await jwe.decrypt(res?.data?.jwe, cek);
        check('ecdh-es: 200 且解回明文含 Hello, ec（下游回显）', plain.includes('Hello, ec'), plain);
    }

    // 6. 未在白名单的 enc 必须被拒（fail-closed）
    {
        const ecKey = keys.byKid.get('ec-gw-2026');
        const {jwe: compact} = await jwe.encrypt(qs.stringify({name: 'ec'}),
            {kid: 'ec-gw-2026', publicKeyJwk: ecKey, uri: '/test/hello', method: 'GET', enc: 'A128GCM'});
        try {
            await axios.get(BASE + '/test/hello', {params: {jwe: compact}});
            check('ecdh-es: A128GCM 未在白名单必须非 200', false);
        } catch (err) {
            check('ecdh-es: A128GCM 未在白名单必须 400', err?.response?.status === 400,
                'status=' + err?.response?.status);
        }
    }

    // 7. 篡改任一字节必须 400（防篡改可执行断言）
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

    process.exitCode = failed === 0 ? 0 : 1;
}

main().catch(err => {
    console.error(err?.response?.status, err?.response?.data || err?.message);
    process.exitCode = 1;
});
