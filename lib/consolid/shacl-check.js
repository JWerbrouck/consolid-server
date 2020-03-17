// Access control logic

const $rdf = require('rdflib');
const SHACLValidator = require('shacl-js')
const fetch = require('node-fetch')
const uuid = require('uuid')
const fs = require('fs')
const exec = require('child_process').exec
const rsa = require('rsa-pem-from-mod-exp')

const ACL = $rdf.Namespace('http://www.w3.org/ns/auth/acl#');
const FOAF = $rdf.Namespace('http://xmlns.com/foaf/0.1/');
const VCARD = $rdf.Namespace('http://www.w3.org/2006/vcard/ns#');
const RDF = $rdf.Namespace('http://www.w3.org/1999/02/22-rdf-syntax-ns#');
const CS = $rdf.Namespace('http://consolid.org/ontology/cs#');
const PAV = $rdf.Namespace('http://purl.org/pav/')
const CERT = $rdf.Namespace('http://www.w3.org/ns/auth/cert#')

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

    function checkSignature(kb, np) {
        // the signature is embedded in the nanopublication, and thus "frozen".
        // I see two ways of verifying: 
            // (1) unstable: check if the public key in the NP matches the one published in the pod of the signing authority

            // (2) verifying the Signature completely (with the public key fetched from the webID)
            
        
        }

    // mistake: not the pubkey of the agent, but of the signing party should be checked
    async function calculateKey(kb, signer) {
        let me = await fetch(signer.value)
        me = await me.text()
        $rdf.parse(me, kb, signer.value, 'text/turtle')
        // let modulus = kb.match(null, CERT('modulus'), null, agent)
        // let exponent = kb.match(null, CERT('exponent'), null, agent)
        // let modulus = `ALqZyYsQ/P51rJi4HAx7q+8xXE8netiJSFgWzO8c5l3FAVv9+riKJ8+fhoPTakB3AO4oBLD3QMZSvXhRRFPuxOOibs/WGz4ntuCb0O8vt09CNrIvBpaN37ZcKMMybHdernXohy9OMEqTUu5ciBuk0XC8/f/Gdrchnb+ySSGD15W20IBLTqchX9IizgKeKTE9m+WoB4OYUf3G5st+VjcJBB+xn8ehbFc5h7MPyUehSPByY6ui6Q66OqgCcLaz4PyZNmt2O3jfjoF3rzQ3/hje/OwUcIAuoyl7GmlOAfrwziTK1A2TngcfGL5d8UTwvUtPPw0AW6t1hbvEVc9nHLlt`
        // let exponent = 'AQAB'
        // modulus = modulus[0].object.value
        // exponent = exponent[0].object.value
        console.log(rsa(modulus, exponent))
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

                            // hack to include localhost NPs (for some reason the ':' in the prefix declaration causes the validation to crash)
                            if (agentValue.includes('localhost:')) {
                                agentValue = agentValue.replace('localhost:8443', 'localhost8443')
                            }
                            text = '@prefix visitor: ' + agentValue + '. \n' + text
                            const me = 'visitor:me'
                            finalText = text.replace(prefixVisitor, me)
                            for (const pub of detail.np) {
                                // console.log(pub.total)
                                let check = await checkAuthenticity(pub.total)
                                console.log(check)

                                // again, the ':' hack for localhost users
                                const assertion = pub.assertion.replace('localhost:', 'localhost')
                                const result = await validate(assertion, finalText, detail.modes)
                                result.forEach(mode => allowedModes.push(mode))
                            }
                        }
                    }
                }
                resolve(allowedModes)
            } catch (error) {
                console.log(error)
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
            // calculateKey(kb, agent)
            resolve(results)
        } catch (error) {
            reject(false)
        }
    })
}


module.exports = shaclDenied