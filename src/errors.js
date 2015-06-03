'use strict';

const util = require('util');

function BadJsonWebTokenError (message) {
	this.name = 'BadJsonWebTokenError';
	this.status = 401;
	this.message = message;
	this.isUserError = true;

	Error.captureStackTrace(this, this.constructor);
}
util.inherits(BadJsonWebTokenError, Error);

function PublicKeyNotFoundError (kid) {
	this.name = 'PublicKeyNotFoundError';
	this.status = 403;
	this.message = `Public key "${ kid }" not found`;
	this.isUserError = true;

	Error.captureStackTrace(this, this.constructor);
}
util.inherits(PublicKeyNotFoundError, Error);

function NoAuthorizationProvidedError () {
	this.name = 'NoAuthorizationProvidedError';
	this.status = 401;
	this.message = 'An authorization method wasn\'t provided';
	this.isUserError = true;

	Error.captureStackTrace(this, this.constructor);
}
util.inherits(NoAuthorizationProvidedError, Error);

module.exports = {
	PublicKeyNotFound: PublicKeyNotFoundError,
	NoAuthorizationProvided: NoAuthorizationProvidedError,
	BadToken: BadJsonWebTokenError
};
