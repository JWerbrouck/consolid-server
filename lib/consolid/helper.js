const Busboy = require('busboy')
const _ = require('lodash')
const fetch = require('node-fetch')

async function extractCertificate(req) {
    return new Promise(async (resolve, reject) => {
        let certificates
        try {
            if (req.headers['content-type'] == 'application/x-www-form-urlencoded' || req.headers['content-type'] == "application/json") {
                if (req.body.certificateText) {
                    certificates = extractCertificatesFromText(req.body.certificateText)
                } else if (req.body.certificateUri) {
                    certificates = await fetchCertificatesByUri(req.body.certificateUri)
                }
            } else if (req.headers['content-type'].startsWith('multipart/form-data')) {
                certificates = await extractFromFormData(req)
            }
            resolve(certificates)
        } catch (error) {
            reject()
        }
    })
}

async function extractCertificatesFromText(certs) {
    let certificates = {}
    try {
        if (Array.isArray(certs)) {
            for (const cert of certs) {
                const { total, prefixes, Head, assertion, provenance, pubinfo, certUri } = await decomposeNP(cert)
                certificates[certUri] = { total, prefixes, Head, assertion, provenance, pubinfo }
            }
            return certificates
        } else {
            const { total, prefixes, Head, assertion, provenance, pubinfo, certUri } = await decomposeNP(certs)
            certificates[certUri] = { total, prefixes, Head, assertion, provenance, pubinfo }
            return certificates
        }
    } catch (error) {
        return {}
    }
}

async function fetchCertificatesByUri(urls) {
    async function fetchNP(url) {
        return new Promise(async (resolve, reject) => {
            try {
                const res = await fetch(url)
                const rawDoc = await res.text()
                const { total, prefixes, Head, assertion, provenance, pubinfo, certUri } = await decomposeNP(rawDoc)
                resolve({ total, prefixes, Head, assertion, provenance, pubinfo, certUri })
            } catch (error) {
                reject()
            }
        })
    }

    return new Promise(async (resolve, reject) => {
        try {
            let certificates = {}
            if (Array.isArray(urls)) {
                for (const url of urls) {
                    if (isURL(url)) {
                        const { total, prefixes, Head, assertion, provenance, pubinfo, certUri } = await fetchNP(url)
                        certificates[certUri] = { total, prefixes, Head, assertion, provenance, pubinfo }
                    }
                }
                resolve(certificates)
            } else if (isURL(urls)) {
                const { total, prefixes, Head, assertion, provenance, pubinfo, certUri } = await fetchNP(urls)
                certificates[certUri] = { total, prefixes, Head, assertion, provenance, pubinfo }
                resolve(certificates)

            } else {
                console.log('rejecting')
                reject()
            }
        } catch (error) {
            reject()
        }
    })
}

function extractFromFormData(req) {
    return new Promise((resolve, reject) => {
        try {
            var busboy = new Busboy({ headers: req.headers });
            let documentData = { certificates: {} }

            busboy.on('file', function (fieldname, file, filename, encoding, mimetype) {
                let buff = ''
                file.on('data', (data) => {
                    buff += data
                });
                file.on('end', async () => {
                    if (fieldname.includes('certificate')) {
                        const { total, prefixes, Head, assertion, provenance, pubinfo, certUri } = await decomposeNP(buff)
                        documentData["certificates"][certUri] = { total, prefixes, Head, assertion, provenance, pubinfo }
                    }
                })
            });

            busboy.on('field', function (fieldname, val, fieldnameTruncated, valTruncated, encoding, mimetype) {
                documentData[fieldname] = val
            });

            busboy.on('finish', function () {
                if (!Object.keys(documentData).includes('certificates')) {
                    reject()
                } else {
                    resolve(documentData.certificates)
                }
            });

            req.pipe(busboy);
        } catch (error) {
            console.log(error)
            reject({})
        }

    })
}

function decomposeNP(total) {
    return new Promise((resolve, reject) => {
        try {
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

            resolve({ total, prefixes, Head, assertion, provenance, pubinfo, certUri })
        } catch (error) {
            reject()
        }
    })
}

function isURL(str) {
    var pattern = new RegExp('^(https?:\\/\\/)?' + // protocol
        '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.?)+[a-z]{2,}|' + // domain name
        '((\\d{1,3}\\.){3}\\d{1,3}))' + // OR ip (v4) address
        '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*' + // port and path
        '(\\?[;&a-z\\d%_.~+=-]*)?' + // query string
        '(\\#[-a-z\\d_]*)?$', 'i'); // fragment locator
    return pattern.test(str);
}



module.exports = extractCertificate