// Access control logic

const $rdf = require('rdflib');
const SHACLValidator = require('shacl-js')
const fetch = require('node-fetch')
const uuid = require('uuid')
const fs = require('fs')
const exec = require('child_process').exec

const ACL = $rdf.Namespace('http://www.w3.org/ns/auth/acl#');
const FOAF = $rdf.Namespace('http://xmlns.com/foaf/0.1/');
const VCARD = $rdf.Namespace('http://www.w3.org/2006/vcard/ns#');
const RDF = $rdf.Namespace('http://www.w3.org/1999/02/22-rdf-syntax-ns#');
const CS = $rdf.Namespace('http://consolid.org/ontology/cs#');
const PAV = $rdf.Namespace('http://purl.org/pav/')

async function shaclDenied(kb, aclDoc, modes, agent, dyncerts) {
    return new Promise(async (resolve, reject) => {
        try {
            const allowedModes = await SHACLmodesAllowed(kb, aclDoc, modes, agent, dyncerts)
            const denied = compareModesAndValidation(modes, allowedModes)
            resolve(denied)
        } catch (error) {
            reject(error)
        }
    })
}

function compareModesAndValidation(reqModes, allowed) {
    let confirmed = []
    reqModes.forEach(mode => {
        if (allowed.includes(mode.value)) {
            confirmed.push(mode)
        }
    })
    if (confirmed.length === reqModes.length) {
        return false
    }
    return true
}


function SHACLmodesAllowed(kb, aclDoc, modes, agent, dyncerts) {
    function getTrustedAuthorities(kb, aclDoc) {
        // for now, only explicitly mentioned authorities count (later: getNearestAuthorities)
        return kb.match(null, CS('hasTrustedAuthority'), null, aclDoc)
    }

    // check, for each rule, if any passed nanopublications are created by any of the trusted authorities mentioned in the rule
    function compareAuthoritiesWithNP(rules, certificates) {
        // putting every certificate in the store
        Object.keys(certificates).forEach(key => {
            const HeadUri = $rdf.sym(key + '.Head')
            const assertionUri = $rdf.sym(key + '.assertion')
            const pubinfoUri = $rdf.sym(key + '.pubinfo')
            const provenanceUri = $rdf.sym(key + '.provenance')
            $rdf.parse(certificates[key].Head, kb, HeadUri.uri, 'text/turtle')
            $rdf.parse(certificates[key].assertion, kb, assertionUri.uri, 'text/turtle')
            $rdf.parse(certificates[key].pubinfo, kb, pubinfoUri.uri, 'text/turtle')
            $rdf.parse(certificates[key].provenance, kb, provenanceUri.uri, 'text/turtle')
            const signingAuthority = kb.match(null, PAV('createdBy'), null, pubinfoUri)[0].object.value + "/profile/card#me"
            certificates[key]['signingAuthority'] = signingAuthority
        })

        let remainingRules = []

        const trustedAuthorities = getTrustedAuthorities(kb, aclDoc)

        rules.forEach(rule => {
            let matchRuleAndNPs = { rule, np: [], shapes: [], modes: [] }
            Object.keys(certificates).forEach(key => {
                trustedAuthorities.forEach(st => {
                    if (rules.includes(st.subject.value)) {
                        if (certificates[key].signingAuthority === st.object.value) {
                            matchRuleAndNPs.np.push({ assertion: certificates[key].assertion, total: certificates[key].total })
                            let shapes = kb.match(null, CS('hasShape'), null, aclDoc)
                            let modes = kb.match(st.subject, ACL('mode'), null, aclDoc)
                            modes.forEach(mode => matchRuleAndNPs.modes.push(mode.object.value))
                            let ruleType
                            if (!kb.holds(st.subject, RDF('type'), CS('ExclusiveRule'), aclDoc)) {
                                ruleType = "inclusive"
                            } else {
                                ruleType = "exclusive"
                            }
                            matchRuleAndNPs.ruleType = ruleType
                            shapes.forEach(shape => matchRuleAndNPs.shapes.push(shape.object.value))
                        }
                    }
                })
            })
            remainingRules.push(matchRuleAndNPs)
        })

        // remainingRules.forEach(rule, index => {
        //   if (rule.rule.np.length == 0) {
        //     rule.splice(index, 1)
        //   }
        // })

        return remainingRules
    }

    async function iterate(details) {
        let allowedModes = []
        return new Promise(async (resolve, reject) => {
            try {
                for (const detail of details) {
                    const alreadyThere = detail.modes.some(m => allowedModes.includes(m))
                    if (!alreadyThere) {
                        for (const sh of detail.shapes) {
                            const res = await fetch(sh)
                            let text = await res.text()

                            // find prefix
                            let prefix = text.split('<http://consolid.org/ontology/cs#>')
                            prefix = prefix[0].split('@prefix ')
                            prefix = prefix[prefix.length - 1].replace(' ', '')
                            // replace prefix
                            prefixVisitor = prefix + 'visitor'
                            let agentValue = agent.value.split('#')
                            agentValue = '<' + agentValue[0] + '#>'
                            text = '@prefix visitor: ' + agentValue + '. \n' + text
                            const me = 'visitor:me'
                            finalText = text.replace(prefixVisitor, me)
                            for (const pub of detail.np) {
                                let check = await checkAuthenticity(pub.total)
                                console.log(check)
                                const result = await validate(pub.assertion, finalText, detail.modes)
                                result.forEach(mode => allowedModes.push(mode))
                            }
                        }
                    }
                }
                resolve(allowedModes)
            } catch (error) {
                reject()
            }
        })
    }

    function validate(np, shape, modes) {
        let validator = new SHACLValidator()
        return new Promise((resolve, reject) => {
            try {
                validator.validate(np, "text/turtle", shape, "text/turtle", function (e, report) {
                    if (report.conforms() === true) {
                        console.log("conforms! hooray")
                        resolve(modes)
                    } else {
                        console.log('does not conform')
                        resolve([])
                    }
                })
            } catch (error) {
                reject(error)
            }
        })
    }

    async function checkAuthenticity(np) {
        try {
            const fileName = uuid.v4() + '.trig'
            const filePath = __dirname + '/' + fileName
            const fullPath = fs.openSync(filePath, 'w')
            fs.writeFileSync(filePath, np)
            return new Promise((resolve, reject) => {
                const command = 'bash ' + __dirname + '/commandline/nanopub/np.sh check ' + filePath
                exec(command, function (err, stdout, stderr) {
                    fs.unlink(filePath, (err) => {
                        if (err) {
                            console.error(err)
                        }})
                    if (stderr) {
                        reject(stderr)
                    } else {
                        if (stdout === 'Summary: 1 trusty with signature;\n') {
                            resolve(stdout)
                        } else {
                            reject(stdout)
                        }
                    }
                })
            })
        } catch (error) {
            console.log(error)
        }
    }

    function executeChildProcess(path) {
        return new Promise((resolve, reject) => {
            const command = 'bash ' + __dirname + '/commandline/nanopub/np.sh check ' + path
            console.log(command)
            exec(command, function (err, stdout, stderr) {
                if (stderr) {
                    console.log(stderr)
                    reject(stderr)
                } else {
                    resolve(stdout)
                }
            })
        })
    }

    return new Promise(async (resolve, reject) => {
        try {
            let dynamicRules = []
            let anyDynamic = kb.match(null, RDF('type'), CS('DynamicRule'), aclDoc)
            anyDynamic.forEach(r => {
                dynamicRules.push(r.subject.value)
            })

            let ruleDetails = compareAuthoritiesWithNP(dynamicRules, dyncerts)
            if (ruleDetails.size == 0) {
                resolve(false)
            }
            let results = await iterate(ruleDetails)
            resolve(results)
        } catch (error) {
            reject(false)
        }
    })
}


module.exports = shaclDenied