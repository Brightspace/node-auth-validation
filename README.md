# brightspace-auth-validation
[![Build Status](https://travis-ci.org/Brightspace/node-auth-validation.svg?branch=master)](https://travis-ci.org/Brightspace/node-auth-validation.svg?branch=master)

## Example

```js
const validator = new (require('brightspace-auth-validation'))();

function *authMiddleware (next) {
	const auth = yield validator.fromHeaders(this.headers);

	this.auth = auth; // BrightspaceAuthToken instance

	yield* next;
};
```

## Testing

```bash
npm test
```

## Contributing

1. **Fork** the repository. Committing directly against this repository is
   highly discouraged.

2. Make your modifications in a branch, updating and writing new unit tests
   as necessary in the `spec` directory.

3. Ensure that all tests pass with `npm test`

4. `rebase` your changes against master. *Do not merge*.

5. Submit a pull request to this repository. Wait for tests to run and someone
   to chime in.

### Code Style

This repository is configured with [EditorConfig][EditorConfig] and
[ESLint][ESLint] rules.

[EditorConfig]: http://editorconfig.org/
[ESLint]: http://eslint.org
