const { LoginRequest } = require('../requests/login-request')
const solid = { auth: require('solid-auth-cli') };

async function verifyUser(req, res) {
    return new Promise(async (resolve, reject) => {
        if (req.headers.authorization) {
            const creds = extractCredentials(req.headers.authorization)
            let user
            try {
                if (creds.idp) {
                    user = await solid.auth.login(creds)
                } else {
                    req.body.username = creds.username
                    req.body.password = creds.password
                    user = await findLocalUser(req, res)
                }
                resolve(user)
            } catch (error) {
                reject(error)
            }
        }
        reject()
    })
}

async function findLocalUser(req, res) {
    let validuser
    return new Promise(async (resolve, reject) => {
        if (typeof req === "object" && req.body.username) {
            try {
              let request = LoginRequest.fromParams(req, res, 'password')
              validuser =  await request.authenticator.findValidUser()
              resolve(validuser)
            } catch (error) {
              reject(error)
            }
          }
    })
}


function extractCredentials(auth) {
    try {
        const basic = auth.split(' ')
        let buff = new Buffer.from(basic[1], 'base64')
        let [un_idp, pw] = buff.toString('ascii').split(':')
        un_idp = un_idp.split('.')
        const un = un_idp.shift()
        let idp
        if (un_idp.length != 0) {
            idp = 'https://'
            un_idp.forEach(i => {
              idp += i + '.'
            })
            idp = idp.substring(0, idp.length - 1) + '/'
        }
        const creds = {idp, username: un, password: pw}
        return creds
    } catch (error) {
        throw new Error(error)
    }
}

module.exports = verifyUser