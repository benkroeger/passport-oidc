'use strict';

process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';

// const assert = require('assert');
const http = require('http');
const express = require('express');
const passport = require('passport');
const OIDCStrategy = require('../lib').Strategy;

// describe('passport-oidc', function () {
//   it('should have unit test!', function () {
//     assert(false, 'we expected this package author to add actual unit tests.');
//   });
// });


const app = express();

app.use(passport.initialize());

passport.use('blueId', new OIDCStrategy({
  identifierField: 'openid_identifier',
  passReqToCallback: true,
  skipUserProfile: true,
  authorizationURL: 'https://prepiam.toronto.ca.ibm.com/idaas/oidc/endpoint/default/authorize',
  tokenURL: 'https://prepiam.toronto.ca.ibm.com/idaas/oidc/endpoint/default/token',
  userInfoURL: '',
  clientID: process.env.OIDC_CLIENT_ID,
  clientSecret: process.env.OIDC_CLIENT_SECRET,
  callbackURL: 'https://logoshub.ibm-sba.com/auth/oidc/callback',
}, (req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, done) => {
  if (jwtClaims && jwtClaims.sub) {
    return done(null, jwtClaims);
  }
  return done(null, false);
}));

app.get('/auth/oidc/login', passport.authenticate('blueId', {
  session: false,
}));

app.get('/auth/oidc/callback', passport.authenticate('blueId', {
  session: false,
}), (req, res) => {
  res.json(req.user);
});


app.server = http.createServer(app);
// Start server
const bindInterface = '127.0.0.1';
const httpPort = 80;
const httpsPort = 443;
app.server.listen(httpPort, bindInterface, () => {
  console.log(`Listening for HTTP requests on ${bindInterface}:${httpPort}`);
});

const https = require('https');
const fs = require('fs');
const path = require('path');
const httpsOpts = {
  key: fs.readFileSync(path.join(__dirname, 'ssl/localhost-key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'ssl/localhost-cer.pem')),
};

https.createServer(httpsOpts, app).listen(httpsPort, bindInterface, () => {
  console.log(`Listening for HTTP requests on ${bindInterface}:${httpsPort}`);
});
