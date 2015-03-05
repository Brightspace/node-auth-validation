'use strict';

const
	assert = require('better-assert'),
	co = require('co'),
	getPem = require('rsa-pem-from-mod-exp'),
	jws = require('jws'),
	jwt = require('jsonwebtoken'),
	request = require('superagent'),
	url = require('url');

const errors = require('./errors');

const
	AUTH_SERVICE_URI = process.env.AUTH_SERVICE_URI || 'https://auth.proddev.d2l:44331',
	AUTH_SERVICE_OPENID_PATH = '/core/.well-known/openid-configuration',
	AUTH_SERVICE_OPENID_URI = url.resolve(AUTH_SERVICE_URI, AUTH_SERVICE_OPENID_PATH),
	MAX_PUBLIC_KEY_AGE = 60 * 60 * 5;

let publicKeys = new Map(),
	publicKeysUpdating;

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

function getJwksUriFromOpenId (openIdConfig) {
	assert('object' === typeof openIdConfig);
	assert('string' === typeof openIdConfig.jwks_uri);

	return openIdConfig.jwks_uri;
}

function processJwks (jwks) {
	assert('object' === typeof jwks);
	assert(Array.isArray(jwks.keys));

	const
		currentPublicKeys = new Map(),
		knownPublicKeys = publicKeys;

	const expiry = clock() + MAX_PUBLIC_KEY_AGE;

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

	publicKeys = currentPublicKeys;
}

const updatePublicKeys = co.wrap(function *updatePublicKeys () {
	const openIdConfig = yield getJsonUri(AUTH_SERVICE_OPENID_URI);
	const jwks = yield getJsonUri(getJwksUriFromOpenId(openIdConfig));
	processJwks(jwks);
});

const getPublicKey = co.wrap(function *getPublicKey (signature) {
	assert('string' === typeof signature);

	const decodedToken = jws.decode(signature);

	assert('object' === typeof decodedToken.header);

	const kid = decodedToken.header.kid;

	assert('string' === typeof kid);

	if (publicKeys.has(kid)) {
		const publicKey = publicKeys.get(kid);

		assert('object' === typeof publicKey);
		assert('string' === typeof publicKey.pem);
		assert('number' === typeof publicKey.expiry);

		if (clock() < publicKey.expiry) {
			return publicKey.pem;
		}
	}

	if (!publicKeysUpdating) {
		publicKeysUpdating = updatePublicKeys().then(function () {
			publicKeysUpdating = undefined;
		});
	}

	yield publicKeysUpdating;

	if (publicKeys.has(kid)) {
		return publicKeys.get(kid).pem;
	}

	throw new errors.PublicKeyNotFound(kid);
});

const getValidatedAuthToken = co.wrap(function *getValidatedAuthToken (headers) {
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

	const key = yield getPublicKey(signature);
	const token = jwt.verify(signature, key);

	return token;
});

module.exports = getValidatedAuthToken;
module.exports.errors = errors;
