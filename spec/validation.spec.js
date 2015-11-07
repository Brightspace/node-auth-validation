/* global describe, it, before, beforeEach, after */

'use strict';

process.env.AUTH_SERVICE_URI = 'http://auth-bar-baz.test.d2l/baz';

const
	BrightspaceAuthToken = require('@d2l/brightspace-auth-token'),
	chai = require('chai'),
	chaiAsPromised = require('chai-as-promised'),
	expect = chai.expect,
	jwt = require('jsonwebtoken'),
	nock = require('nock'),
	NodeRSA = require('node-rsa'),
	rsaPemToJwk = require('rsa-pem-to-jwk');

const
	ISSUER = process.env.AUTH_SERVICE_URI,
	JWKS_PATH = '/.well-known/jwks';

const AuthTokenValidator = require('../');

chai.use(chaiAsPromised);

describe('validations', function () {
	let
		error,
		jwkInterceptor,
		token,
		validator;

	const
		privateKeyPem = new NodeRSA({ b: 512 }).exportKey('pkcs1-private-pem') + '\n',
		jwk = rsaPemToJwk(privateKeyPem, { kid: 'foo-bar-baz', use: 'sig' }, 'public');

	before(function (done) {
		nock.enableNetConnect();
		done();
	});

	beforeEach(function (done) {
		error = undefined;
		jwkInterceptor = undefined;
		token = undefined;
		validator = new AuthTokenValidator({
			issuer: ISSUER
		});
		done();
	});

	after(function (done) {
		nock.cleanAll();
		done();
	});

	it('should throw "NoAuthorizationProvided" when there is no auth header', function *() {
		expect(validator.fromHeaders({}))
			.to.be.rejectedWith(AuthTokenValidator.errors.NoAuthorizationProvided);
	});

	it('should throw "NoAuthorizationProvided" when auth header is not a Bearer token', function *() {
		expect(validator.fromHeaders({ authorization: 'Basic foobarbaz' }))
			.to.be.rejectedWith(AuthTokenValidator.errors.NoAuthorizationProvided);
	});

	it('should throw "BadToken" when invalid token is sent', function *() {
		yield expect(validator.fromHeaders({ authorization: 'Bearer foobarbaz' }))
			.to.be.rejectedWith(AuthTokenValidator.errors.BadToken);
	});

	it('should throw "BadToken" when expired token is sent', function *() {
		token = jwt.sign({}, privateKeyPem, {
			algorithm: 'RS256',
			headers: {
				kid: 'foo-bar-baz'
			},
			expiresInSeconds: -1
		});

		jwkInterceptor = nock(ISSUER)
			.replyContentLength()
			.get(JWKS_PATH)
			.reply(200, {
				keys: [jwk]
			});

		yield expect(validator.fromHeaders({ authorization: `Bearer ${ token }` }))
			.to.be.rejectedWith(AuthTokenValidator.errors.BadToken);

		jwkInterceptor.done();
	});

	it('should throw "BadToken" for bad signature', function *() {
		token = jwt.sign({}, privateKeyPem, {
			algorithm: 'RS256',
			headers: {
				kid: 'foo-bar-baz'
			}
		});

		token += 'mess-up-the-signature';

		jwkInterceptor = nock(ISSUER)
			.replyContentLength()
			.get(JWKS_PATH)
			.reply(200, {
				keys: [jwk]
			});

		yield expect(validator.fromHeaders({ authorization: `Bearer ${token}` }))
			.to.be.rejectedWith(AuthTokenValidator.errors.BadToken);

		jwkInterceptor.done();
	});

	it('should throw "PublicKeyNotFound" when no key with matching "kid" is found on auth server', function *() {
		token = jwt.sign({}, privateKeyPem, {
			algorithm: 'RS256',
			headers: {
				kid: 'errmegerd'
			}
		});

		jwkInterceptor = nock(ISSUER)
			.replyContentLength()
			.get(JWKS_PATH)
			.reply(200, {
				keys: [jwk]
			});

		yield expect(validator.fromHeaders({ authorization: `Bearer ${ token }` }))
			.to.be.rejectedWith(AuthTokenValidator.errors.PublicKeyNotFound);

		jwkInterceptor.done();
	});

	it('should throw "PublicKeyLookupFailed" when there is an error requesting the jwks', function *() {
		token = jwt.sign({}, privateKeyPem, {
			algorithm: 'RS256',
			headers: {
				kid: 'errmegerd'
			}
		});

		jwkInterceptor = nock(ISSUER)
			.replyContentLength()
			.get(JWKS_PATH)
			.reply(404);

		yield expect(validator.fromHeaders({ authorization: `Bearer ${ token }` }))
			.to.be.rejectedWith(AuthTokenValidator.errors.PublicKeyLookupFailed);

		jwkInterceptor.done();
	});

	it('should NOT throw "PublicKeyLookupFailed" when there WAS error requesting the jwks', function *() {
		token = jwt.sign({}, privateKeyPem, {
			algorithm: 'RS256',
			headers: {
				kid: 'errmegerd'
			}
		});

		jwkInterceptor = nock(ISSUER)
			.replyContentLength()
			.get(JWKS_PATH)
			.reply(404);

		yield expect(validator.fromHeaders({ authorization: `Bearer ${ token }` }))
			.to.be.rejectedWith(AuthTokenValidator.errors.PublicKeyLookupFailed);

		jwkInterceptor.done();

		const
			payload = {
				key: 'val'
			},
			signature = jwt.sign(payload, privateKeyPem, {
				algorithm: 'RS256',
				headers: {
					kid: 'foo-bar-baz'
				}
			});

		jwkInterceptor = nock(ISSUER)
			.replyContentLength()
			.get(JWKS_PATH)
			.reply(200, {
				keys: [jwk]
			});

		token = yield validator.fromHeaders({
			authorization: `Bearer ${ signature }`
		});
		expect(token).to.be.instanceof(BrightspaceAuthToken);
		expect(token.source).to.equal(signature);

		jwkInterceptor.done();
	});

	it('should return BrightspaceAuthToken when matching "kid" is found on auth server and signature is valid', function *() {
		const
			payload = {
				key: 'val'
			},
			signature = jwt.sign(payload, privateKeyPem, {
				algorithm: 'RS256',
				headers: {
					kid: 'foo-bar-baz'
				}
			});

		jwkInterceptor = nock(ISSUER)
			.replyContentLength()
			.get(JWKS_PATH)
			.reply(200, {
				keys: [jwk]
			});

		token = yield validator.fromHeaders({
			authorization: `Bearer ${ signature }`
		});
		expect(token).to.be.instanceof(BrightspaceAuthToken);
		expect(token.source).to.equal(signature);

		jwkInterceptor.done();
	});

	describe('validateConfiguration', function () {
		it('should return true when public keys can be updated', function *() {
			jwkInterceptor = nock(ISSUER)
				.get(JWKS_PATH)
				.reply(200, {
					keys: [jwk]
				});

			const auth = new AuthTokenValidator({
				issuer: ISSUER
			});

			yield expect(auth.validateConfiguration()).to.eventually.be.true;

			jwkInterceptor.done();
		});

		it('should return an error when public key lookup fails', function *() {
			jwkInterceptor = nock(ISSUER)
				.get(JWKS_PATH)
				.reply(404);

			const auth = new AuthTokenValidator({
				issuer: ISSUER
			});

			yield expect(auth.validateConfiguration()).to.be.rejectedWith(Error);
		});
	});
});
