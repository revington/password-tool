'use strict';

const crypto = require('crypto'),
    bcrypt = require('bcryptjs');

const BCRYPT_SALT_ROUNDS=10,
    IV_LEN = 16,
    ALGORITHM =  'AES-256-CTR';

function sha512(input){
    let hasher = crypto.createHash('SHA512');
    hasher.update(input);
    return hasher.digest('base64');
}

function encrypt (key, input) {
    const IV = new Buffer(crypto.randomBytes(IV_LEN));

    let cipher = crypto.createCipheriv(ALGORITHM, key, IV);
    cipher.setEncoding('base64');
    cipher.write(input);
    cipher.end();

    const cipherText = cipher.read();

    // IV is not a secret. We can store it along the password
    return cipherText + '$' + IV.toString('base64');
}

function hashAndEncryptPassword(key, input, callback){
    let sha512hash ;
    try{
        sha512hash = sha512(input);
    }catch(err){
        return callback(err);
    }
    bcrypt.hash(sha512hash, BCRYPT_SALT_ROUNDS, function(err, result){
        var encryptedHash;
        if(err){
            return callback(err);
        }
        try{
            encryptedHash = encrypt(key, result);
        }catch(err){
            return callback(err);
        }

        callback( null, encryptedHash);
    });
}

function decrypt(key, input){
    var result;
    let [cipherText, IV] = input.split('$');
    let buffIV = new Buffer(IV, 'base64');
    let decipher = crypto.createDecipheriv(ALGORITHM, key, buffIV);
    result = decipher.update(cipherText, 'base64', 'utf8');
    result += decipher.final('utf8');
    return result;
}

function compare(key, clearPassword, encryptedPassword, callback){
    var hash;
    try{
        hash = decrypt(key, encryptedPassword);
    }catch(err){
        return callback(err);
    }
    bcrypt.compare(sha512(clearPassword), hash, callback);
}

exports.hashAndEncryptPassword = hashAndEncryptPassword;
exports.compare = compare;
