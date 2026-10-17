'use strict';
/**
 * v2 协议演示（WebCrypto + JWKS）：GET / POST(json) / POST(form) 三条请求。
 * 需先启动 web-example（8081）；前端跑法：node front/index.js
 *
 * @author changgg
 */
const jwe = require('./encryptor/jwe')
const axios = require('axios');
const qs = require('qs');

const BASE = 'http://127.0.0.1:8081';
const JWKS_URL = BASE + '/.well-known/encryptor-keys';

/**
 * 带"400 → 强制刷新 JWKS → 重试一次"的请求执行器（应对服务端换 kid）。
 */
async function call(makeRequest) {
    let keys = await jwe.fetchKeys(JWKS_URL);
    try {
        return await makeRequest(keys);
    } catch (err) {
        if (err?.response?.status !== 400) {
            throw err;
        }
        keys = await jwe.fetchKeys(JWKS_URL, true);
        return await makeRequest(keys);
    }
}

function currentKey(keys) {
    return {kid: keys.activeKid, publicKeyJwk: keys.byKid.get(keys.activeKid)};
}

/** 响应统一是 {"jwe": "..."}，用请求的 CEK 解开。 */
async function decryptResponse(res, cek) {
    return jwe.decrypt(res?.data?.jwe, cek);
}

async function main() {
    console.log('test get');
    await call(async keys => {
        const {jwe: compact, cek} = await jwe.encrypt(qs.stringify({name: '1'}),
            {...currentKey(keys), uri: '/test/hello', method: 'GET'});
        const res = await axios.get(BASE + '/test/hello', {params: {jwe: compact}});
        console.log('post:' + await decryptResponse(res, cek));
    });

    console.log('test post(json)');
    await call(async keys => {
        const {jwe: compact, cek} = await jwe.encrypt(JSON.stringify({name: '1'}),
            {...currentKey(keys), uri: '/test/hello', method: 'POST'});
        const res = await axios.post(BASE + '/test/hello', {jwe: compact},
            {headers: {'Content-Type': 'application/json'}});
        console.log('post:' + await decryptResponse(res, cek));
    });

    console.log('test post(application/x-www-form-urlencoded)');
    await call(async keys => {
        const {jwe: compact, cek} = await jwe.encrypt(qs.stringify({name: '1'}),
            {...currentKey(keys), uri: '/test/hello', method: 'POST'});
        const res = await axios.post(BASE + '/test/hello', qs.stringify({jwe: compact}),
            {headers: {'Content-Type': 'application/x-www-form-urlencoded'}});
        console.log('post:' + await decryptResponse(res, cek));
    });
}

main().catch(err => {
    console.error(err?.response?.status, err?.response?.data || err?.message);
    process.exitCode = 1;
});
