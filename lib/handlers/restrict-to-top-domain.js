const HTTPError = require('../http-error')

module.exports = function (req, res, next) {
  console.log('restricted')
  const locals = req.app.locals
  const ldp = locals.ldp
  const serverUri = locals.host.serverUri
  const hostname = ldp.resourceMapper.resolveUrl(req.hostname)
  console.log(req.hostname)
  console.log(req.serverUri)
  if (hostname === serverUri) {
    return next()
  }
  const isLoggedIn = !!(req.session && req.session.userId)
  return next(new HTTPError(isLoggedIn ? 403 : 401, 'Not allowed to access top-level APIs on accounts'))
}
