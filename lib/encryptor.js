const crypto = require('crypto');
let _logger;

/**
 * Generates a code by making a cipher and signature and combining them.
 * @param text
 * @returns {string}
 */
function createCode(text, secret) {
    try {
        return aesCipher(text, secret) + '.' + createSignature(text, secret);
    } catch (err) {
        _logger.error(err);
        throw err;
    }
}

/**
 * Parses the message to an object.
 * @param code
 * @param messageParser, is required and MOST return an object with the property exp!
 * @returns Object
 */
function decryptCode(code, secret, messageParser) {
    code = code.split(' ').join('+'); // replace spaces with + again
    const linkdata = code.split('.');
    const encryptedData = linkdata[0];
    const signature = linkdata[1];
    let msg;
    try {
        msg = aesDecipher(encryptedData, secret);
    } catch (e) {
        throw new Error('Invalid code');
    }
    if (!verify(msg, signature, secret)) {
        throw new Error('Invalid signature');
    }
    const data = messageParser(msg);

    if (!isValid(data.exp)) { // experation check
        throw new Error('Code is outdated');
    }
    return data;
}

/**
 * Creates a cipher used for making encryption.
 * @param text
 * @returns {*}
 */
function aesCipher(text, secret) {
    try {
        const iv = Buffer.alloc(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secret, 'base64'), iv);
        return cipher.update(text, 'utf8', 'base64') + cipher.final('base64');
    } catch (err) {
        _logger.error(err);
        throw new Error(err);
    }
}

/**
 * Deciphers the cipher
 * @param data
 * @returns {*}
 */
function aesDecipher(data, secret) {
    try {
        const iv = Buffer.alloc(16);
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secret, 'base64'), iv, 'utf8');
        let dec = decipher.update(data, 'base64', 'utf8');
        dec += decipher.final('utf8');
        return dec;
    } catch (err) {
        _logger.error(err);
        throw new Error(err);
    }
}

/**
 * Creates a encrypted signature
 * @param text
 * @returns {PromiseLike<ArrayBuffer>}
 */
function createSignature(text, secret) {
    try {
        return crypto.createHmac('sha256', secret).update(text).digest('base64');
    } catch (err) {
        _logger.error(err);
        throw new Error(err);
    }
}

/**
 * Checks if the given exp value is still valid
 */

/* exp is unix-timestamp */
function isValid(exp) {
    try {
        return Date.now() <= exp;
    } catch (err) {
        _logger.error(err);
        throw new Error(err);
    }
}

/**
 * Compares the signature to the createdSignature for a given message
 * @param msg
 * @param signature
 * @returns {boolean}
 */
function verify(msg, signature, secret) {
    try {
        return signature === createSignature(msg, secret);
    } catch (err) {
        _logger.error(err);
        throw new Error(err);
    }
}


module.exports = (logger)=>{
    _logger = logger;
    return {createCode, readCode};
};
