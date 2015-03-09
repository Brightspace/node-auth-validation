/* global after, before, beforeEach, describe, it */

'use strict';

const
	expect = require('chai').expect,
	jwt = require('jsonwebtoken'),
	nock = require('nock'),
	NodeRSA = require('node-rsa'),
	rsaPemToJwk = require('rsa-pem-to-jwk');

const
	ISSUER = 'http://auth-bar-baz.test.d2l/baz',
	JWKS_PATH = '/this-is-the-place-the-jwks-is';

const AuthTokenValidator = require('../');

describe('validations', function () {
	let jwk,
		privateKeyPem,
		openIdInterceptor,
		validator;
	before(function () {
		privateKeyPem = new NodeRSA({ b: 512 }).exportKey('pkcs1-private-pem') + '\n';
		jwk = rsaPemToJwk(privateKeyPem, { kid: 'foo-bar-baz', use: 'sig' }, 'public');

		openIdInterceptor = nock(ISSUER)
			.replyContentLength()
			.get('/.well-known/openid-configuration')
			.times(2)
			.reply(200, {
				jwks_uri: ISSUER + JWKS_PATH
			});
	});

	beforeEach(function () {
		validator = new AuthTokenValidator({
			issuer: ISSUER
		});
	});

	after(function () {
		openIdInterceptor.done();
	});

	it('should throw "NoAuthorizationProvided" when there is no auth header', function *() {
		let err;
		try {
			yield validator.fromHeaders({});
		} catch (e) {
			err = e;
		}

		expect(err).to.be.an.instanceof(AuthTokenValidator.errors.NoAuthorizationProvided);
	});

	it('should throw "NoAuthorizationProvided" when auth header is not a Bearer token', function *() {
		let err;
		try {
			yield validator.fromHeaders({
				authorization: 'Basic foobarbaz'
			});
		} catch (e) {
			err = e;
		}

		expect(err).to.be.an.instanceof(AuthTokenValidator.errors.NoAuthorizationProvided);
	});

	it('should throw "PublicKeyNotFound" when no key with matching "kid" is found on auth server', function *() {
		const jwksInterceptor = nock(ISSUER)
			.replyContentLength()
			.get(JWKS_PATH)
			.reply(200, {
				keys: [jwk]
			});

		let err;
		try {
			const token = jwt.sign({}, privateKeyPem, {
				algorithm: 'RS256',
				header: {
					kid: 'errmegerd'
				}
			});
			yield validator.fromHeaders({
				authorization: `Bearer ${ token }`
			});
		} catch (e) {
			err = e;
		}

		expect(err).to.be.an.instanceof(AuthTokenValidator.errors.PublicKeyNotFound);
		jwksInterceptor.done();
	});

	it('should return JWT when matching "kid" is found on auth server and signature is valid', function *() {
		const jwksInterceptor = nock(ISSUER)
			.replyContentLength()
			.get(JWKS_PATH)
			.reply(200, {
				keys: [jwk]
			});

		const
			payload = { key: 'val' },
			signature = jwt.sign(payload, privateKeyPem, {
				algorithm: 'RS256',
				header: {
					kid: 'foo-bar-baz'
				}
			});

		const token = yield validator.fromHeaders({
			authorization: `Bearer ${ signature }`
		});

		expect(token).to.deep.equal(payload);

		jwksInterceptor.done();
	});
});
