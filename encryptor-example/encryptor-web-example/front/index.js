const aes = require('./encryptor/aes')
const rsa = require('./encryptor/rsa')
const signature = require('./encryptor/md5withaes.signature')
const random = require('./encryptor/random')
const axios = require('axios');
const qs = require('qs');

const rsaPublicKey = "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGETAZi4hJ6ZxQWhHvM22BRivGOg/PzFo9+KNjAPwpzGkHkklQ1meB9kWYXo10VVDE6mXpzHFfPq1Lww1sRRAZs2oMib+hUqx67Mai93oEcQrzt31e4M6Ulscfnz9XwG9/TAoWoIdGU8S5ZNUihfTPkbUAJ7KQ60FpAgHF8mb/ljAgMBAAE=";
const key = aes.generateBase64Key(128);
const options = {
    iv: random.getRandomStr(16), mode: 'CBC', padding: 'PKCS5Padding', key
};
console.log('test get')
{
    const data = {
        'nonce': random.getRandomStr(24),
        'timestamp': new Date().getTime(),
        'key': rsa.encrypt_base64(options, rsaPublicKey),
        'data': aes.encrypt_base64({
            'name': '1'
        }, key, options)
    }
    data['signature'] = signature.signature(data['nonce'] + data['timestamp'] + data['data'], key, options);
    axios.get('http://127.0.0.1:8081/test/hello', {
        'params': data
    })
            .then(res => res?.data)
            .then(res => {
                console.log("pre:" + JSON.stringify(res));
                console.log("post:" + aes.decrypt_base64(res?.data, key, options));
            }).catch(err => console.log(err?.response?.data, data))
}
console.log('test post')
{
    const data = {
        'nonce': random.getRandomStr(24),
        'timestamp': new Date().getTime(),
        'key': rsa.encrypt_base64(options, rsaPublicKey),
        'data': aes.encrypt_base64({
            'name': '1'
        }, key, options)
    }
    data['signature'] = signature.signature(data['nonce'] + data['timestamp'] + data['data'], key, options);
    axios.post('http://127.0.0.1:8081/test/hello', data)
            .then(res => res?.data)
            .then(res => {
                console.log("pre:" + JSON.stringify(res));
                console.log("post:" + aes.decrypt_base64(res?.data, key, options));
            }).catch(err => console.log(err?.response?.data, data))
}
console.log('test post(application/application/x-www-form-urlencoded)')
{
    const data = {
        'nonce': random.getRandomStr(24),
        'timestamp': new Date().getTime(),
        'key': rsa.encrypt_base64(options, rsaPublicKey),
        'data': aes.encrypt_base64(qs.stringify({
            'name': '1'
        }), key, options)
    }
    data['signature'] = signature.signature(data['nonce'] + data['timestamp'] + data['data'], key, options);
    axios.post('http://127.0.0.1:8081/test/hello', qs.stringify(data), {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    })
            .then(res => res?.data)
            .then(res => {
                console.log("pre:" + JSON.stringify(res));
                console.log("post:" + aes.decrypt_base64(res?.data, key, options));
            }).catch(err => console.log(err?.response?.data, data))
}