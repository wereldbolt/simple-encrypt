const test = require('tape');
const log = (m) => process.stdout.write(m);
const error = (e) => log(e.message);
const encryptor = require('../')({log: log, error: error});

/**
* Create with openssl an secret string, for example:
* openssl rand -base64 32 # 256-bit secret
*/

const testSecret = "C2TQUXOwOCRt2VJYzK2bkl33dXh4V0ovnjWCjxnza+A=";

test('Create code', function (t) {

	const expiration = 10000000000;
    const exp = Date.now() + expiration;

    const secretMessagePartA = 'abc';
    const secretMessagePartB = 'def';
    const msg = `${exp}/${secretMessagePartA}/${secretMessagePartB}`;

    const code = encryptor.createCode(msg, testSecret);
    const result = encryptor.readCode(code, testSecret, (msg)=>{
        const data = msg.split('/');
        return {
            exp: data[0],
            partA: data[1],
            partB: data[2]
        };
    });

    t.equal(result.partA, 'abc');
    t.equal(result.partB, 'def');
    t.end();
});




