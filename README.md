CredentialsLib
=======

[![NPM Package](https://img.shields.io/npm/v/credentials-lib.svg?style=flat-square)](https://www.npmjs.org/package/credentials-lib)
[![Build Status](https://img.shields.io/travis/owstack/credentials-lib.svg?branch=master&style=flat-square)](https://travis-ci.org/owstack/credentials-lib)
[![Coverage Status](https://img.shields.io/coveralls/owstack/credentials-lib.svg?style=flat-square)](https://coveralls.io/r/owstack/credentials-lib)

A JavaScript cryptocurrency credentials library.

## Get Started

```
npm install credentials-lib
```

```
bower install credentials-lib
```

## Documentation

The complete docs are hosted here: [CredentialsLib documentation](docs/index.md).

## Examples

* [Seed from Random](docs/credentials.md#seed-from-random)
* [Seed from Random with specified mnemonic](docs/credentials.md#seed-from-random-with-mnemonic)
* [Seed from Extended Private Key](docs/credentials.md#seed-from-extended-private-key)
* [Seed from Mnemonic](docs/credentials.md#seed-from-mnemonic)
* [Seed from External Wallet Public Key](docs/credentials.md#seed-from-extended-public-key)

## Security

If you find a security issue, please email security@openwalletstack.com.

## Contributing

Please send pull requests for bug fixes, code optimization, and ideas for improvement. For more information on how to contribute, please refer to our [CONTRIBUTING](https://github.com/owstack/key-lib/blob/master/CONTRIBUTING.md) file.

## Building the Browser Bundle

To build a key-lib full bundle for the browser:

```sh
gulp browser
```

This will generate files named `credenitials-lib.js` and `credentials-lib.min.js`.

## Development & Tests

```sh
git clone https://github.com/owstack/credenitials-lib
cd credenitials-lib
npm install
```

Run all the tests:

```sh
gulp test
```

You can also run just the Node.js tests with `gulp test:node`, just the browser tests with `gulp test:browser`
or create a test coverage report (you can open `coverage/lcov-report/index.html` to visualize it) with `gulp coverage`.

## License

Code released under [the MIT license](https://github.com/owstack/credentials-lib/blob/master/LICENSE).

Copyright 2018 Open Wallet Stack. CredentialsLib is a trademark maintained by Open Wallet Stack.
