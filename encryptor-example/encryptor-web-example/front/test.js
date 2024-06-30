const aes = require('./encryptor/aes')
const rsa = require('./encryptor/rsa')

//测试aes
{
    const key = "e10adc3949ba59abbe56e057f20f883e";
    const options = {
        iv: key.substring(0, 16),
        mode: 'CBC', padding: 'PKCS5Padding',
    };
    const decrypt = aes.encrypt_base64({'a': 1, 'b': 2}, key, options);
    console.log(decrypt);
    console.log(aes.decrypt_base64(decrypt, key, options));
}
{
    const publicKey = "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGNChr14yXkgoXSOdrHXsTx24DfK/eUbduu05ooN9xijYKN5lLDNOpdtKKIpTszSGWxMlrdCZVVI6nOUYiyEWBmdwS0+crSPD3ukEqMc0jkoDtpRXi23tv1ssyjzewf+dtphieyrggaGM9CKVGSP1ZbYQoQ4daWf/tB8SdimM/4FAgMBAAE=";
    const privateKey = "MIICWgIBAAKBgGNChr14yXkgoXSOdrHXsTx24DfK/eUbduu05ooN9xijYKN5lLDNOpdtKKIpTszSGWxMlrdCZVVI6nOUYiyEWBmdwS0+crSPD3ukEqMc0jkoDtpRXi23tv1ssyjzewf+dtphieyrggaGM9CKVGSP1ZbYQoQ4daWf/tB8SdimM/4FAgMBAAECgYBin647QnGE7dwecJMU/4g12LPOG96Lru9JIdRS5a9XhrW1mE8aIMCPxsEx5rNKJZNnHO4/pjQDOlDhiFTHgLP7ewMcXVLkob0Vy5X6En1wJk5fHo2x17NZ1k254ZPii9FX0mZ5w4ky45SeKgSqk+KMjNFIOjEsG5JVIsrUJyIUQQJBAKJ+Vq4Gw1wSmZXc3qRwNCfu6YQ4bDCarKQ64Kh6JXLdXMyRegftUFWNhi58Vo9H3o8GJgTIaAsNr5dmyNWxUzUCQQCcYPN5Tdj8ulujiWayb4Z3R3EHF8hCvDXy5ShOWJb4M1nEnB9dRaxm2X5rarZxscXcFeMs16ez41adsJE5WwmRAkBbKwszBLRjWkQ1owB/vjxlE1SNTKLW+lFWq3oUzMNqGOzSEeUnwWxLM+ZO+pAOP8KM+GQoVtCZMwqLpa2Ux7LpAkAPLs6U2X0W1JUvJJkG/BMHI7WSpbl42UM3qQ4nxSwrPvkZQLs+2BPsDHPcxAigs0ztmGZtJScQLSNsvgbrla4xAkAf3vRDITNBLo2Vr9BmjCHDoIjAxkKt71NoS+S+MZWayHJ4LxAnbcSXKsziQ2tlCjR3MkNRiBFZnsqkUH6/5cJs";
    const decrypt = rsa.encrypt_base64({'a': 1, 'b': 2}, publicKey);
    console.log(decrypt);
    console.log(rsa.decrypt_base64(decrypt, privateKey));
}
