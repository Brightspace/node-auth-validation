/* global describe, it */

'use strict';

const expect = require('chai').expect;

const
	errors = require('../src/errors'),
	pkgExport = require('../');

describe('errors', function () {
	it('should be available on ".errors"', function (done) {
		expect(pkgExport.errors).to.be.a('object');
		done();
	});

	it('should include "BadTokenError"', function (done) {
		expect(pkgExport.errors.BadToken).to.equal(errors.BadToken);
		done();
	});

	it('should include "NoAuthizationProvidedError"', function (done) {
		expect(pkgExport.errors.NoAuthorizationProvided).to.equal(errors.NoAuthorizationProvided);
		done();
	});

	it('should include "PublicKeyNotFounddError"', function (done) {
		expect(pkgExport.errors.PublicKeyNotFound).to.equal(errors.PublicKeyNotFound);
		done();
	});
});
