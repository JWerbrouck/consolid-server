const fs = require('fs')

function SignNanoPublicationRequest (req, res) {
    console.log(req.body)
    return res.json('test')
}

module.exports = SignNanoPublicationRequest