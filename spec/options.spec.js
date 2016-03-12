'use strict';

const expect = require('chai').expect;

const AuthTokenValidator = require('../');

describe('options', () => {
	describe('maxClockSkew', () => {
		function constructWithOption(maxClockSkew) {
			return () => new AuthTokenValidator({ maxClockSkew });
		}

		it('should throw a TypeError if not a Number', () => {
			expect(constructWithOption(null)).to.throw(TypeError, /maxClockSkew/);
			expect(constructWithOption('60')).to.throw(TypeError, /maxClockSkew/);
			expect(constructWithOption({})).to.throw(TypeError, /maxClockSkew/);
			expect(constructWithOption(true)).to.throw(TypeError, /maxClockSkew/);
		});

		it('should throw a TypeError if a negative Number', () => {
			expect(constructWithOption(-1)).to.throw(TypeError, /maxClockSkew/);
		});

		it('should use the provided value if a non-negative Number', () => {
			expect(constructWithOption(0)())
				.to.have.a.property('_maxClockSkew')
				.that.equals(0);
			expect(constructWithOption(20)())
				.to.have.a.property('_maxClockSkew')
				.that.equals(20);
		});

		it('should use the default value if undefined', () => {
			expect(constructWithOption()())
				.to.have.a.property('_maxClockSkew')
				.that.equals(5 * 60);
		});
	});
});
