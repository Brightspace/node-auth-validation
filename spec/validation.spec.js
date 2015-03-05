/* global after, before, describe, it */

'use strict';

const
	base64Url = require('base64-url'),
	expect = require('chai').expect,
	jwt = require('jsonwebtoken'),
	nock = require('nock'),
	NodeRSA = require('node-rsa');

const
	ISSUER = 'http://auth-bar-baz.test.d2l/baz',
	JWKS_PATH = '/this-is-the-place-the-jwks-is';

const AuthTokenValidator = require('../');

describe('validations', function () {
	let key,
		privateKeyPem,
		openIdInterceptor,
		validator;
	before(function () {
		key = new NodeRSA({ b: 512 });
		privateKeyPem = key.exportKey('pkcs1-private-pem');

		openIdInterceptor = nock(ISSUER)
			.replyContentLength()
			.get('/.well-known/openid-configuration')
			.times(2)
			.reply(200, {
				jwks_uri: ISSUER + JWKS_PATH
			});

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
				keys: [{
					kid: 'errmegerd',
					n: '1234',
					e: '8484'
				}]
			});

		let err;
		try {
			const token = jwt.sign({}, privateKeyPem, {
				algorithm: 'RS256',
				header: {
					kid: 'foo-bar-baz'
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
		const
			e = (function (exp) {
				const buf = new Buffer(3);
				buf.writeUIntBE(exp, 0, 3);
				return base64Url.escape(buf.toString('base64'));
			})(key.keyPair.e),
			n = base64Url.escape(key.keyPair.n.toBuffer().toString('base64'));

		const jwksInterceptor = nock(ISSUER)
			.replyContentLength()
			.get(JWKS_PATH)
			.reply(200, {
				keys: [{
					kid: 'foo-bar-baz',
					n: n,
					e: e
				}]
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
