# brightspace-auth-validation
[![Build Status](https://magnum.travis-ci.com/Brightspace/node-auth-validation.svg?token=M9m6audKHodN5pA44rGq&branch=master)](https://magnum.travis-ci.com/Brightspace/node-auth-validation)

## Example

```js
const validator = new (require('brightspace-auth-validation'))();

function *authMiddleware (next) {
	const auth = yield validator.fromHeaders(this.headers);

	this.auth = auth; // @d2l/BrightspaceAuthToken instance

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

This repository is configured with [EditorConfig][EditorConfig], [jscs][jscs]
and [JSHint][JSHint] rules. See the [docs.dev code style article][code style]
for information on installing editor extensions.

[EditorConfig]: http://editorconfig.org/
[jscs]: http://jscs.info/
[JSHint]: http://jshint.com/
[code style]: http://docs.dev.d2l/index.php/JavaScript_Code_Style_(Personal_Learning)
