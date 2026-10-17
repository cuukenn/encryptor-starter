'use strict';
/**
 * 端到端断言脚本：GET / POST(json) / POST(form) / JWKS 四条，全过 exit 0，任一失败 exit 1。
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
        check('get: 200 且解回明文含 name=1', plain.includes('name=1'), plain);
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
        check('post-form: 200 且解回明文含 name=1', plain.includes('name=1'), plain);
    }

    // 5. 篡改任一字节必须 400（防篡改可执行断言）
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
