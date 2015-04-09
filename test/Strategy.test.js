var chai = require('chai');
var assert = chai.assert;
var WindowsLiveTokenStrategy = require('../');
var fakeProfile = JSON.stringify(require('./fixtures/profile.json'));

describe('WindowsLiveTokenStrategy:init', function () {
  it('Should properly export Strategy constructor', function () {
    assert.equal(typeof WindowsLiveTokenStrategy, 'function');
    assert.equal(typeof WindowsLiveTokenStrategy.Strategy, 'function');
    assert.equal(WindowsLiveTokenStrategy, WindowsLiveTokenStrategy.Strategy);
  });

  it('Should properly initialize', function () {
    var strategy = new WindowsLiveTokenStrategy({
      clientID: '123',
      clientSecret: '123'
    }, function () {
    });

    assert.equal(strategy.name, 'windows-live-token');
  });
});

describe('WindowsLiveTokenStrategy:authenticate', function () {
  describe('Authenticate without passReqToCallback', function () {
    var strategy;

    before(function () {
      strategy = new WindowsLiveTokenStrategy({
        clientID: '123',
        clientSecret: '123'
      }, function (accessToken, refreshToken, profile, next) {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      strategy._oauth2.get = function (url, accessToken, next) {
        next(null, fakeProfile, null);
      };
    });

    it('Should properly parse access_token', function (done) {
      chai.passport.use(strategy)
        .success(function (user, info) {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(function (req) {
          req.headers = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly call fail if access_token is not provided', function (done) {
      chai.passport.use(strategy)
        .fail(function (error) {
          assert.typeOf(error, 'object');
          assert.typeOf(error.message, 'string');
          assert.equal(error.message, 'You should provide access_token');
          done();
        })
        .authenticate();
    });
  });

  describe('Authenticate with passReqToCallback', function () {
    var strategy;

    before(function () {
      strategy = new WindowsLiveTokenStrategy({
        clientID: '123',
        clientSecret: '123',
        passReqToCallback: true
      }, function (req, accessToken, refreshToken, profile, next) {
        assert.typeOf(req, 'object');
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      strategy._oauth2.get = function (url, accessToken, next) {
        next(null, fakeProfile, null);
      }
    });

    it('Should properly call _verify with req', function (done) {
      chai.passport.use(strategy)
        .success(function (user, info) {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(function (req) {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });
  });
});

describe('WindowsLiveTokenStrategy:userProfile', function () {
  it('Should properly fetch profile', function (done) {
    var strategy = new WindowsLiveTokenStrategy({
      clientID: '123',
      clientSecret: '123'
    }, function () {
    });

    strategy._oauth2.get = function (url, accessToken, next) {
      next(null, fakeProfile, null);
    };

    strategy.userProfile('accessToken', function (error, profile) {
      if (error) return done(error);

      assert.equal(profile.provider, 'windows-live');
      assert.equal(profile.id, '8c8ce076ca27823f');
      assert.equal(profile.displayName, 'Roberto Tamburello');
      assert.equal(profile.name.familyName, 'Tamburello');
      assert.equal(profile.name.givenName, 'Roberto');
      assert.equal(profile.emails[0].value, 'Roberto@contoso.com');
      assert.equal(profile.emails[0].type, 'account');
      assert(profile.emails[0].primary);
      assert.notOk(profile.emails[1].primary);
      assert.notOk(profile.emails[2].primary);
      assert.notOk(profile.emails[3].primary);
      assert.equal(profile.emails[1].value, 'Roberto@fabrikam.com');
      assert.equal(profile.emails[1].type, 'home');
      assert.equal(profile.emails[2].value, 'Robert@adatum.com');
      assert.equal(profile.emails[2].type, 'work');
      assert.equal(profile.emails[3].value, 'Roberto@adventure-works.com');
      assert.equal(profile.emails[3].type, 'other');
      assert.equal(profile.photos[0].value, 'https://apis.live.net/v5.0/8c8ce076ca27823f/picture');
      assert.equal(typeof profile._raw, 'string');
      assert.equal(typeof profile._json, 'object');

      done();
    });
  });

  it('Should properly handle exception on fetching profile', function (done) {
    var strategy = new WindowsLiveTokenStrategy({
      clientID: '123',
      clientSecret: '123'
    }, function () {
    });

    strategy._oauth2.get = function (url, accessToken, done) {
      done(null, 'not a JSON', null);
    };

    strategy.userProfile('accessToken', function (error, profile) {
      assert(error instanceof SyntaxError);
      assert.equal(typeof profile, 'undefined');
      done();
    });
  });
});
