# garbados-crypt

[![CI](https://github.com/garbados/crypt/actions/workflows/ci.yaml/badge.svg)](https://github.com/garbados/crypt/actions/workflows/ci.yaml)
[![Coverage Status](https://coveralls.io/repos/github/garbados/crypt/badge.svg?branch=master)](https://coveralls.io/github/garbados/crypt?branch=master)
[![Stability](https://img.shields.io/badge/stability-stable-green.svg?style=flat-square)](https://nodejs.org/api/documentation.html#documentation_stability_index)
[![NPM Version](https://img.shields.io/npm/v/garbados-crypt.svg?style=flat-square)](https://www.npmjs.com/package/garbados-crypt)
[![JS Standard Style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/feross/standard)

Easy password-based encryption, by [garbados](https://garbados.github.io/my-blog/).

This library attempts to reflect [informed opinions](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html) while respecting realities like resource constraints, tech debt, and so on. The idea is to provide some very simple methods that just do the hard thing for you.

For example:

```javascript
const Crypt = require('garbados-crypt')

const crypt = new Crypt(password)
const encrypted = await crypt.encrypt('hello world')
console.log(encrypted)
> "O/z1zXHQ+..."
const decrypted = await crypt.decrypt(encrypted)
console.log(decrypted)
> "hello world"
```

Crypt only works with plaintext, so remember to use `JSON.stringify()` on objects before encryption and `JSON.parse()` after decryption. For classes and the like, you'll need to choose your own encoding / decoding approach.

Crypt works in the browser, too! You can require it like this:

```html
<script src="https://raw.githubusercontent.com/garbados/crypt/master/bundle.min.js" charset="utf-8"></script>
<script type="text/javascript">
// now you can encrypt in the browser! 26kb!
const crypt = new Crypt('a very good password')
</script>
```

You can also require it with [browserify](https://www.npmjs.com/package/browserify) or [webpack](https://www.npmjs.com/package/webpack), of course.

## Install

Use [npm](https://www.npmjs.com/) or whatever.

```bash
$ npm i -S garbados-crypt
```

## Usage

First, require the library. Then get to encrypting!

```javascript
const Crypt = require('garbados-crypt')

const crypt = new Crypt(password)
```

### new Crypt(password)

- `password`: A string. Make sure it's good! Or not.

### async crypt.encrypt(plaintext) => ciphertext

- `plaintext`: A string.
- `ciphertext`: A different, encrypted string.

### async crypt.decrypt(ciphertext) => plaintext

- `ciphertext`: An encrypted string produced by `crypt.encrypt()`.
- `plaintext`: The decrypted message as a string.

If decryption fails, for example because your password is incorrect, an error will be thrown.

## Development

First, get the source:

```bash
$ git clone git@github.com:garbados/crypt.git garbados-crypt
$ cd garbados-crypt
$ npm i
```

Use the test suite:

```bash
$ npm test
```

The test suite includes a small benchmarking test, which runs on the server and in the browser, in case you're curious about performance.

To see test coverage:

```bash
$ npm run cov
```

## Also: How To Securely Store A Password

For a password-based encryption system, it makes sense to have a good reference on how to store passwords in a database. To this effect I have written [this gist](https://gist.github.com/garbados/29ca945d5964ef85e7936804c23edb9d#file-how_to_store_passwords-js) to demonstrate safe password obfuscation and verification. If you have any issue with the advice offered there, leave a comment!

## Why TweetNaCl.js?

This library uses [tweetnacl](https://www.npmjs.com/package/tweetnacl) rather than native crypto. You might have feelings about this.

I chose it because it's fast on NodeJS, bundles conveniently (33kb!), uses top-shelf algorithms, and has undergone a [reasonable audit](https://www.npmjs.com/package/tweetnacl#audits).

That said, I'm open to PRs that replace it with native crypto while retaining Crypt's API.

## License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
