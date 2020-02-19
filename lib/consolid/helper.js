const Busboy = require('busboy')
const _ = require('lodash')

async function extractCertificate(req) {
    return new Promise(async (resolve, reject) => {
        try {
            var busboy = new Busboy({ headers: req.headers });
            let documentData = {certificates: {}}

            busboy.on('file', function (fieldname, file, filename, encoding, mimetype) {
                let buff = ''
                file.on('data', (data) => {
                    buff += data
                });
                file.on('end', () => {
                    if (fieldname.includes('certificate')) {
                        const {total, prefixes, Head, assertion, provenance, pubinfo, certUri} = decomposeNP(buff)
                        documentData["certificates"][certUri] = {total, prefixes, Head, assertion, provenance, pubinfo}
                    } else {
                        documentData[fieldname] = buff
                    }
                })
            });

            busboy.on('field', function (fieldname, val, fieldnameTruncated, valTruncated, encoding, mimetype) {
                documentData[fieldname] = val
            });

            busboy.on('finish', function () {
                if (_.isEmpty(documentData)) {
                    reject({})
                } else {
                    resolve(documentData)
                }
            });

            req.pipe(busboy);
        } catch (error) {
            reject({})
        }

    })
}

function decomposeNP (total) {
    // rdflib.js does not read trig files
    // isolate certificate URI
    let certUri = total.split('@prefix this:').pop()
    certUri = certUri.split('<')[1].split('>')[0]

    // isolate prefixes
    let prefixes = ''
    let prefix = total.split('\n')
    prefix.forEach(pr => {
        if (pr.startsWith('@prefix')) {
            prefixes += pr + "\n"
        }
    });

    let parts = total.split('}')
    // isolate head
    let Head = prefixes + parts[0].split('{').pop()
    // isolate assertion
    let assertion = prefixes + parts[1].split('{').pop()
    // isolate provenance
    let provenance = prefixes + parts[2].split('{').pop()
    // isolate pubinfo
    let pubinfo = prefixes + parts[3].split('{').pop()

    return {total, prefixes, Head, assertion, provenance, pubinfo, certUri}
}

module.exports = extractCertificate