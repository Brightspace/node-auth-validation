'use strict';

const
	assert = require('better-assert'),
	AuthToken = require('@d2l/brightspace-auth-token'),
	co = require('co'),
	getPem = require('rsa-pem-from-mod-exp'),
	jws = require('jws'),
	jwt = require('jsonwebtoken'),
	request = require('superagent');

const errors = require('./errors');

const
	DEFAULT_ISSUER = 'https://auth.proddev.d2l:44331/core',
	DEFAULT_MAX_KEY_AGE = 5 * 60 * 60,
	OPENID_PATH = '/.well-known/openid-configuration';

function clock () {
	return Math.round(Date.now() / 1000);
}

function getJsonUri (uri) {
	assert('string' === typeof uri);

	return new Promise(function (resolve, reject) {
		request
			.get(uri)
			.end(function (err, res) {
				if (err) {
					reject(err);
					return;
				}

				resolve(res.body);
			});
	});
}

function processJwks (jwks, knownPublicKeys, maxKeyAge) {
	assert('object' === typeof jwks);
	assert(Array.isArray(jwks.keys));
	assert(knownPublicKeys instanceof Map);
	assert('number' === typeof maxKeyAge);

	const
		currentPublicKeys = new Map(),
		expiry = clock() + maxKeyAge;

	for (let jwk of jwks.keys) {
		assert('object' === typeof jwk);
		assert('string' === typeof jwk.kid);
		assert('string' === typeof jwk.e);
		assert('string' === typeof jwk.n);

		const pem = knownPublicKeys.has(jwk.kid)
			? knownPublicKeys.get(jwk.kid).pem
			: getPem(jwk.n, jwk.e);

		currentPublicKeys.set(jwk.kid, {
			expiry: expiry,
			pem: pem
		});
	}

	return currentPublicKeys;
}

function AuthTokenValidator (opts) {
	if (!(this instanceof AuthTokenValidator)) {
		return new AuthTokenValidator(opts);
	}

	opts = opts || {};

	const issuer = 'string' === typeof opts.issuer ? opts.issuer.replace(/\/+$/g, '') : DEFAULT_ISSUER;

	this._openIdUri = `${ issuer }${ OPENID_PATH }`;
	this._maxKeyAge = 'number' === typeof opts.maxKeyAge ? opts.maxKeyAge : DEFAULT_MAX_KEY_AGE;
	this._keyCache = new Map();
	this._keysUpdating = null;
}

AuthTokenValidator.prototype.fromHeaders = function getValidatedAuthTokenFromHeaders (headers) {
	assert('object' === typeof headers);

	const authHeader = headers.authorization;
	if (!authHeader) {
		throw new errors.NoAuthorizationProvided();
	}

	const signatureMatch = authHeader.match(/^Bearer (.+)$/);
	if (!signatureMatch) {
		throw new errors.NoAuthorizationProvided();
	}

	const signature = signatureMatch[1];

	return this.fromSignature(signature);
};

AuthTokenValidator.prototype.fromSignature = co.wrap(function *getValidatedAuthTokenFromSignature (signature) {
	assert('string' === typeof signature);

	const key = yield this._getPublicKey(signature);
	const payload = jwt.verify(signature, key);

	const token = new AuthToken(payload, signature);

	return token;
});

AuthTokenValidator.prototype._getPublicKey = function *getPublicKey (signature) {
	assert('string' === typeof signature);

	const decodedToken = jws.decode(signature);

	assert('object' === typeof decodedToken.header);

	const kid = decodedToken.header.kid;

	assert('string' === typeof kid);

	if (this._keyCache.has(kid)) {
		const publicKey = this._keyCache.get(kid);

		assert('object' === typeof publicKey);
		assert('string' === typeof publicKey.pem);
		assert('number' === typeof publicKey.expiry);

		if (clock() < publicKey.expiry) {
			return publicKey.pem;
		}
	}

	if (!this._keysUpdating) {
		const self = this;

		this._keysUpdating = this
			._updatePublicKeys()
			.then(function () {
				self._keysUpdating = null;
			});
	}

	yield this._keysUpdating;

	if (this._keyCache.has(kid)) {
		return this._keyCache.get(kid).pem;
	}

	throw new errors.PublicKeyNotFound(kid);
};

AuthTokenValidator.prototype._updatePublicKeys = co.wrap(function *updatePublicKeys () {
	const openIdConfig = yield getJsonUri(this._openIdUri);
	const jwks = yield getJsonUri(openIdConfig.jwks_uri);

	this._keyCache = processJwks(jwks, this._keyCache, this._maxKeyAge);
});

module.exports = AuthTokenValidator;
module.exports.errors = errors;
