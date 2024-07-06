const aes = require('./encryptor/aes')
const rsa = require('./encryptor/rsa')
const signature = require('./encryptor/md5withaes.signature')
const random = require('./encryptor/random')
const qs = require('qs');
const axios = require('axios');

const rsaPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCpT0+GwrgJmO7z8SY151PYQArVdlX68b2PLXH7s0CbPIqUqAZigwD2D5QiAIWQzLWq7af4L51ZvYn5VJPIcKOQqX86e3WfoBnj0+R6E9RbOQEuvkatZn/rX0WWNqOhK+U6ga3YWEfANeT9gGAaf3JH7aOM62BQd1gdsKKncLeY7QIDAQAB";
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
    axios.get('http://127.0.0.1:8080/test/hello', {
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
    axios.post('http://127.0.0.1:8080/test/hello', data)
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
    axios.post('http://127.0.0.1:8080/test/hello', qs.stringify(data), {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    })
            .then(res => res?.data)
            .then(res => {
                console.log("pre:" + JSON.stringify(res));
                console.log("post:" + aes.decrypt_base64(res?.data, key, options));
            }).catch(err => console.log(err?.response?.status, err?.response?.statusText, data))
}