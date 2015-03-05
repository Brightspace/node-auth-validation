/* global after, before, describe, it */

'use strict';

const
	base64Url = require('base64-url'),
	expect = require('chai').expect,
	jwt = require('jsonwebtoken'),
	nock = require('nock'),
	NodeRSA = require('node-rsa'),
	url = require('url');

const
	AUTH_SERVICE_URI = require('./__env').AUTH_SERVICE_URI,
	JWKS_PATH = '/this-is-the-place-the-jwks-is';

const getValidatedAuthToken = require('../');

describe('validations', function () {
	let key,
		privateKeyPem,
		openIdInterceptor;
	before(function () {
		key = new NodeRSA({ b: 512 });
		privateKeyPem = key.exportKey('pkcs1-private-pem');

		openIdInterceptor = nock(AUTH_SERVICE_URI)
			.replyContentLength()
			.get('/core/.well-known/openid-configuration')
			.times(2)
			.reply(200, {
				jwks_uri: url.resolve(AUTH_SERVICE_URI, JWKS_PATH)
			});
	});

	after(function () {
		openIdInterceptor.done();
	});

	it('should throw "NoAuthorizationProvided" when there is no auth header', function *() {
		let err;
		try {
			yield getValidatedAuthToken({});
		} catch (e) {
			err = e;
		}

		expect(err).to.be.an.instanceof(getValidatedAuthToken.errors.NoAuthorizationProvided);
	});

	it('should throw "NoAuthorizationProvided" when auth header is not a Bearer token', function *() {
		let err;
		try {
			yield getValidatedAuthToken({
				authorization: 'Basic foobarbaz'
			});
		} catch (e) {
			err = e;
		}

		expect(err).to.be.an.instanceof(getValidatedAuthToken.errors.NoAuthorizationProvided);
	});

	it('should throw "PublicKeyNotFound" when no key with matching "kid" is found on auth server', function *() {
		const jwksInterceptor = nock(AUTH_SERVICE_URI)
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
			yield getValidatedAuthToken({
				authorization: `Bearer ${ token }`
			});
		} catch (e) {
			err = e;
		}

		expect(err).to.be.an.instanceof(getValidatedAuthToken.errors.PublicKeyNotFound);
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

		const jwksInterceptor = nock(AUTH_SERVICE_URI)
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

		const token = yield getValidatedAuthToken({
			authorization: `Bearer ${ signature }`
		});

		expect(token).to.deep.equal(payload);

		jwksInterceptor.done();
	});
});
