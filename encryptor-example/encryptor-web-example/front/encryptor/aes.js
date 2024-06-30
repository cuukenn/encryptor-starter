const CryptoJS = require('crypto-js');
const random = require('./random')
const modes = {
    'CBC': CryptoJS.mode.CBC,
}
const paddings = {
    'PKCS5Padding': CryptoJS.pad.Pkcs7,
}
const convertOptions = (options) => {
    if (!options) {
        return {}
    }
    return {
        mode: modes[options?.mode],
        padding: paddings[options?.padding],
        iv: options?.iv ? CryptoJS.enc.Utf8.parse(options?.iv) : null,
    }
}
const generateBase64Key = (size) => {
    return btoa(random.getRandomStr(size / 8));
}
const decrypt = (data, key, options) => {
    const keyL = CryptoJS.enc.Base64.parse(key);
    return CryptoJS.AES.decrypt(data, keyL, convertOptions(options));
}
const encrypt = (data, key, options) => {
    const dataL = typeof data === 'string' ? data : JSON.stringify(data);
    const keyL = CryptoJS.enc.Base64.parse(key);
    return CryptoJS.AES.encrypt(dataL, keyL, convertOptions(options));
}
const decrypt_base64 = (data, key, options) => {
    return decrypt(data, key, options).toString(CryptoJS.enc.Utf8);
}
const encrypt_base64 = (data, key, options) => {
    return encrypt(data, key, options).toString();
}
module.exports = {
    decrypt,
    encrypt,
    encrypt_base64,
    decrypt_base64,
    generateBase64Key
}
