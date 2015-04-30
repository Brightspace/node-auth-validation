/* global describe, it, before, beforeEach, after */

'use strict';

process.env.AUTH_SERVICE_URI = 'http://auth-bar-baz.test.d2l/baz';

const
	BrightspaceAuthToken = require('@d2l/brightspace-auth-token'),
	expect = require('chai').expect,
	jwt = require('jsonwebtoken'),
	nock = require('nock'),
	NodeRSA = require('node-rsa'),
	rsaPemToJwk = require('rsa-pem-to-jwk');

const
	ISSUER = process.env.AUTH_SERVICE_URI,
	JWKS_PATH = '/.well-known/jwks';

const AuthTokenValidator = require('../');

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
		try {
			yield validator.fromHeaders({});
		} catch (e) {
			error = e;
		}

		expect(error).to.be.an.instanceof(AuthTokenValidator.errors.NoAuthorizationProvided);
	});

	it('should throw "NoAuthorizationProvided" when auth header is not a Bearer token', function *() {
		try {
			yield validator.fromHeaders({
				authorization: 'Basic foobarbaz'
			});
		} catch (e) {
			error = e;
		}

		expect(error).to.be.an.instanceof(AuthTokenValidator.errors.NoAuthorizationProvided);
	});

	it('should throw "BadToken" when invalid token is sent', function *() {
		try {
			yield validator.fromHeaders({
				authorization: 'Bearer foobarbaz'
			});
		} catch (e) {
			error = e;
		}
		expect(error).to.be.an.instanceof(AuthTokenValidator.errors.BadToken);
	});

	it('should throw "BadToken" when expired token is sent', function *() {
		token = jwt.sign({}, privateKeyPem, {
			algorithm: 'RS256',
			header: {
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

		try {
			yield validator.fromHeaders({
				authorization: `Bearer ${ token }`
			});
		} catch (e) {
			error = e;
		}
		expect(error).to.be.an.instanceof(AuthTokenValidator.errors.BadToken);
		jwkInterceptor.done();
	});

	it('should throw "PublicKeyNotFound" when no key with matching "kid" is found on auth server', function *() {
		token = jwt.sign({}, privateKeyPem, {
			algorithm: 'RS256',
			header: {
				kid: 'errmegerd'
			}
		});

		jwkInterceptor = nock(ISSUER)
			.replyContentLength()
			.get(JWKS_PATH)
			.reply(200, {
				keys: [jwk]
			});

		try {
			yield validator.fromHeaders({
				authorization: `Bearer ${ token }`
			});
		} catch (e) {
			error = e;
		}
		expect(error).to.be.an.instanceof(AuthTokenValidator.errors.PublicKeyNotFound);
		jwkInterceptor.done();
	});

	it('should return BrightspaceAuthToken when matching "kid" is found on auth server and signature is valid', function *() {
		const
			payload = {
				key: 'val'
			},
			signature = jwt.sign(payload, privateKeyPem, {
				algorithm: 'RS256',
				header: {
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
});
