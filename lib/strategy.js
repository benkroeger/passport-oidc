'use strict';
/**
 * Module dependencies.
 */
var url = require('url');
var querystring = require('querystring');
var util = require('util');

var passport = require('passport');
var OAuth2 = require('oauth').OAuth2;

var utils = require('./utils');
var InternalOAuthError = require('./errors/internaloautherror');


/**
 * `Strategy` constructor.
 *
 * The OpenID Connect authentication strategy authenticates requests using
 * OpenID Connect, which is an identity layer on top of the OAuth 2.0 protocol.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function OpenIDConnectStrategy(options, verify) {
  var self = this;
  if (typeof options === 'function') {
    verify = options;
    options = {};
  }
  if (!verify && typeof verify === 'function') {
    throw new TypeError('OpenIDConnectStrategy requires a verify function');
  }

  passport.Strategy.call(this);

  options = util._extend({
    scopeSeparator: ' ',
    passReqToCallback: false,
    skipUserProfile: false
  }, options);

  // this._scope = options.scope;

  if (!options.authorizationURL) {
    throw new TypeError('OpenIDConnectStrategy requires options.authorizationURL');
  }

  if (!options.tokenURL) {
    throw new TypeError('OpenIDConnectStrategy requires options.tokenURL');
  }

  if (!options.clientID) {
    throw new TypeError('OpenIDConnectStrategy requires options.clientID');
  }

  if (!options.clientSecret) {
    throw new TypeError('OpenIDConnectStrategy requires options.clientSecret');
  }

  if (!options.callbackURL) {
    throw new TypeError('OpenIDConnectStrategy requires options.callbackURL');
  }

  // userInfoUrl is only required if skipUserProfile resolves to true
  if (options.skipUserProfile !== true && !options.userInfoURL) {
    throw new TypeError('OpenIDConnectStrategy requires options.userInfoURL when userProfile is not skipped');
  }

  Object.keys(options).forEach(function (key) {
    self[`_${key}`] = options[key];
  });

  this.name = 'openidconnect';
  this._verify = verify;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(OpenIDConnectStrategy, passport.Strategy);


/**
 * Authenticate request by delegating to an OpenID Connect provider.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
OpenIDConnectStrategy.prototype.authenticate = function (req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return self.fail(req.query.error);
  }

  var config = [
    'clientID',
    'clientSecret',
    'authorizationURL',
    'tokenURL',
    'callbackURL',
    'userInfoURL'
  ].reduce(function (result, key) {
    result[key] = self[`_${key}`];
    return result;
  }, {});

  var callbackURL = options.callbackURL || config.callbackURL;
  if (callbackURL && !url.parse(callbackURL).protocol) {
    // The callback URL is relative, resolve a fully qualified URL from the
    // URL of the originating request.
    callbackURL = url.resolve(utils.originalURL(req), callbackURL);
  }

  if (req.query && req.query.code) {
    var code = req.query.code;

    // clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders
    var oauth2 = new OAuth2(config.clientID, config.clientSecret, '', config.authorizationURL, config.tokenURL);

    oauth2.getOAuthAccessToken(code, {
      grant_type: 'authorization_code',
      redirect_uri: callbackURL
    }, function (err, accessToken, refreshToken, params) {
      if (err) {
        return self.error(new InternalOAuthError('failed to obtain access token', err));
      }

      var idToken = params.id_token;
      if (!idToken) {
        return self.error(new Error('ID Token not present in token response'));
      }

      var idTokenSegments = idToken.split('.');
      var jwtClaimsStr;
      var jwtClaims;

      // @TODO: validate jwt signature (algorithm, key)

      try {
        jwtClaimsStr = new Buffer(idTokenSegments[1], 'base64').toString();
        jwtClaims = JSON.parse(jwtClaimsStr);
      } catch (ex) {
        return self.error(ex);
      }

      // [
      //   'sub',        // subject - Asserts the identity of the user
      //   'iss',        // Specifies the issuing authority
      //   'aud',        // Is generated for a particular audience, i.e. client
      //   'nonce',      // May contain a nonce
      //   'auth_time',  // May specify when (auth_time) and how,
      //   'acr',        // in terms of strength (acr), the user was authenticated.
      //   'iat',        // Has an issue (iat)
      //   'exp'        // and an expiration date (exp).
      // ]

      // May include additional requested details about the subject, such as name and email address.
      // Is digitally signed, so it can be verified by the intended recipients.
      // May optionally be encrypted for confidentiality.

      // TODO: Ensure claims are validated per:
      //       http://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation

      var iss = jwtClaims.iss;
      var sub = jwtClaims.sub;

      self._shouldLoadUserProfile(iss, sub, function (err, load) {
        if (err) {
          return self.error(err);
        }

        if (load) {
          var parsed = url.parse(config.userInfoURL, true);
          parsed.query.schema = 'openid';
          delete parsed.search;
          var userInfoURL = url.format(parsed);

          // allow oauth to use Authorization header for get requests
          oauth2.useAuthorizationHeaderforGET(true);
          oauth2.get(userInfoURL, accessToken, function (err, body) {
            if (err) {
              return self.error(new InternalOAuthError('failed to fetch user profile', err));
            }

            var profile = {};

            try {
              var json = JSON.parse(body);

              profile.id = json.sub;
              profile.displayName = json.name;
              profile.name = {
                familyName: json.family_name,
                givenName: json.given_name,
                middleName: json.middle_name
              };

              profile._raw = body;
              profile._json = json;

              onProfileLoaded(profile);
            } catch (ex) {
              return self.error(ex);
            }
          });
        } else {
          onProfileLoaded();
        }

        function onProfileLoaded(profile) {
          function verified(err, user, info) {
            if (err) {
              return self.error(err);
            }
            if (!user) {
              return self.fail(info);
            }
            self.success(user, info);
          }

          var arity;
          if (self._passReqToCallback) {
            arity = self._verify.length;
            if (arity === 9) {
              self._verify(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
            } else if (arity === 8) {
              self._verify(req, iss, sub, profile, accessToken, refreshToken, params, verified);
            } else if (arity === 7) {
              self._verify(req, iss, sub, profile, accessToken, refreshToken, verified);
            } else if (arity === 5) {
              self._verify(req, iss, sub, profile, verified);
            } else { // arity === 4
              self._verify(req, iss, sub, verified);
            }
          } else {
            arity = self._verify.length;
            if (arity === 8) {
              self._verify(iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
            } else if (arity === 7) {
              self._verify(iss, sub, profile, accessToken, refreshToken, params, verified);
            } else if (arity === 6) {
              self._verify(iss, sub, profile, accessToken, refreshToken, verified);
            } else if (arity === 4) {
              self._verify(iss, sub, profile, verified);
            } else { // arity === 3
              self._verify(iss, sub, verified);
            }
          }
        }
      });
    });
  } else {

    var params = util._extend(self.authorizationParams(options), {
      response_type: 'code',
      client_id: config.clientID,
      redirect_uri: callbackURL
    });

    var scope = options.scope || self._scope;
    if (Array.isArray(scope)) {
      scope = scope.join(self._scopeSeparator);
    }
    if (scope) {
      params.scope = 'openid' + self._scopeSeparator + scope;
    } else {
      params.scope = 'openid';
    }

    // TODO: Add support for automatically generating a random state for verification.
    // var state = options.state || utils.uid(16);
    // if (state) {
    //   params.state = state;
    // }

    // TODO: Implement support for standard OpenID Connect params (display, prompt, etc.)
    // http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

    var location = config.authorizationURL + '?' + querystring.stringify(params);
    self.redirect(location);
  }
};


/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OpenID Connect providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OpenID Connect specification, OpenID Connect-based
 * authentication strategies can overrride this function in order to populate
 * these parameters as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
OpenIDConnectStrategy.prototype.authorizationParams = function () {
  return {};
};

/**
 * Check if should load user profile, contingent upon options.
 *
 * @param {String} issuer
 * @param {String} subject
 * @param {Function} done
 * @api private
 */
OpenIDConnectStrategy.prototype._shouldLoadUserProfile = function (issuer, subject, done) {
  if (typeof this._skipUserProfile === 'function' && this._skipUserProfile.length > 2) {
    // async
    return this._skipUserProfile(issuer, subject, function (err, skip) {
      if (err) {
        return done(err);
      }
      if (!skip) {
        return done(null, true);
      }
      return done(null, false);
    });
  }

  var skip = typeof this._skipUserProfile === 'function' ? this._skipUserProfile(issuer, subject) : this._skipUserProfile;
  if (!skip) {
    return done(null, true);
  }
  return done(null, false);
};


/**
 * Expose `OpenIDConnectStrategy`.
 */
module.exports = OpenIDConnectStrategy;

