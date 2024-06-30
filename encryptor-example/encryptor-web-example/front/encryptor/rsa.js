const forge = require('node-forge');

const wrap_publicKey2pem = (key) => {
    return `-----BEGIN PUBLIC KEY-----${key}-----END PUBLIC KEY-----`
}
const wrap_privateKey2pem = (key) => {
    return `-----BEGIN PRIVATE KEY-----${key}-----END PRIVATE KEY-----`
}
const encrypt_base64 = (data, key) => {
    const pem = forge.pki.publicKeyFromPem(wrap_publicKey2pem(key));
    return forge.util.encode64(pem.encrypt(typeof data === 'string' ? data : JSON.stringify(data)), 'RSAES-PKCS1-V1_5');
}
const decrypt_base64 = (data, key) => {
    const pem = forge.pki.privateKeyFromPem(wrap_privateKey2pem(key));
    const encryptedBuffer = Buffer.from(data, 'base64');
    const encryptedBytes = forge.util.createBuffer(encryptedBuffer.toString('binary'));
    const decryptedBytes = pem.decrypt(encryptedBytes.bytes(), 'RSAES-PKCS1-V1_5');
    return decryptedBytes.toString();
}
module.exports = {
    encrypt_base64,
    decrypt_base64
}