'use strict';
const passwordTool = require('..');
const key = 'BKYHAT11zlXUiXE3iZfzSEWfvwjdbfPK';
const password = 'super secret';
const assert = require('assert');

describe('Password Tool',function(){
    var match;
    before(function(done){
        passwordTool.hashAndEncryptPassword(key, password, function(err, hash){
            if(err){
                return done(err);
            }
            passwordTool.compare(key, password, hash, function (err, result){
                if(err){
                    return done(err);
                }
                match = result;
                done();
            });
        });
    });
    it('Plain passwords should match their hashed and encrypted versions',function(){
        assert(match);
    });
});
