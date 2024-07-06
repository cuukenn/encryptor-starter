const CryptoJS = require('crypto-js');
const aes = require('./aes');
const signature = (data, key, options) => {
    return aes.encrypt_base64(CryptoJS.MD5(data).toString(), key, options);
}
module.exports = {
    signature
}
