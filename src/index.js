import { OAuth2Strategy, InternalOAuthError } from 'passport-oauth';

/**
 * `Strategy` constructor.
 * The Windows Live authentication strategy authenticates requests by delegating to Windows Live using OAuth2 access tokens.
 * Applications must supply a `verify` callback which accepts a accessToken, refreshToken, profile and callback.
 * Callback supplying a `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occurs, `error` should be set.
 *
 * Options:
 * - clientID          Identifies client to Windows Live App
 * - clientSecret      Secret used to establish ownership of the consumer key
 * - passReqToCallback If need, pass req to verify callback
 *
 * @param {Object} _options
 * @param {Function} _verify
 * @example
 * passport.use(new WindowsLiveTokenStrategy({
 *   clientID: '123456789',
 *   clientSecret: 'shhh-its-a-secret'
 * }), function(accessToken, refreshToken, profile, next) {
 *   User.findOrCreate({windowsId: profile.id}, function(error, user) {
 *     next(error, user);
 *   })
 * });
 */
export default class WindowsLiveTokenStrategy extends OAuth2Strategy {
  constructor(_options, _verify) {
    let options = _options || {};
    let verify = _verify;

    options.authorizationURL = options.authorizationURL || 'https://login.live.com/oauth20_authorize.srf';
    options.tokenURL = options.tokenURL || 'https://login.live.com/oauth20_token.srf';

    super(options, verify);

    this.name = 'windows-live-token';
    this._accessTokenField = options.accessTokenField || 'access_token';
    this._refreshTokenField = options.refreshTokenField || 'refresh_token';
    this._profileURL = options.profileURL || 'https://apis.live.net/v5.0/me';
    this._passReqToCallback = options.passReqToCallback;
  }

  /**
   * Authenticate method
   * @param {Object} req
   * @param {Object} options
   * @returns {*}
   */
  authenticate(req, options) {
    let accessToken = (req.body && req.body[this._accessTokenField]) || (req.query && req.query[this._accessTokenField]);
    let refreshToken = (req.body && req.body[this._refreshTokenField]) || (req.query && req.query[this._refreshTokenField]);

    if (!accessToken) return this.fail({message: `You should provide ${this._accessTokenField}`});

    this._loadUserProfile(accessToken, (error, profile) => {
      if (error) return this.error(error);

      const verified = (error, user, info) => {
        if (error) return this.error(error);
        if (!user) return this.fail(info);

        return this.success(user, info);
      };

      if (this._passReqToCallback) {
        this._verify(req, accessToken, refreshToken, profile, verified);
      } else {
        this._verify(accessToken, refreshToken, profile, verified);
      }
    });
  }

  /**
   * Parse user profile
   * @param {String} accessToken Windows Live OAuth2 access token
   * @param {Function} done
   */
  userProfile(accessToken, done) {
    this._oauth2.get(this._profileURL, accessToken, (error, body, res) => {
      if (error) {
        try {
          let errorJSON = JSON.parse(error.data);
          return done(new InternalOAuthError(errorJSON.error.message, errorJSON.error.code));
        } catch (_) {
          return done(new InternalOAuthError('Failed to fetch user profile', error));
        }
      }

      try {
        let json = JSON.parse(body);
        let profile = {
          provider: 'windows-live',
          id: json.id,
          username: json.username || '',
          displayName: json.name || '',
          name: {
            familyName: json.last_name || '',
            givenName: json.first_name || ''
          },
          emails: [],
          photos: [{
            value: 'https://apis.live.net/v5.0/' + json.id + '/picture'
          }],
          _raw: body,
          _json: json
        };

        if (json.emails && json.emails.account) profile.emails.push({value: json.emails.account, type: 'account'});
        if (json.emails && json.emails.personal) profile.emails.push({value: json.emails.personal, type: 'home'});
        if (json.emails && json.emails.business) profile.emails.push({value: json.emails.business, type: 'work'});
        if (json.emails && json.emails.other) profile.emails.push({value: json.emails.other, type: 'other'});

        if (json.emails && json.emails.preferred) {
          for (let i = 0; i < profile.emails.length; i++) {
            if (profile.emails[i].value == json.emails.preferred) {
              profile.emails[i].primary = true;
            }
          }
        }

        return done(null, profile);
      } catch (e) {
        return done(e);
      }
    });
  }
}
