'use strict';

var owsCommon = require('@owstack/ows-common');
var Base58Check = owsCommon.encoding.Base58Check;
var BufferUtil = owsCommon.buffer;
var Constants = owsCommon.Constants;
var keyLib = require('@owstack/key-lib');
var Hash = owsCommon.Hash;
var Mnemonic = require('@owstack/mnemonic-lib');
var Networks = require('@owstack/network-lib');
var sjcl = require('sjcl');
var lodash = owsCommon.deps.lodash;
var $ = require('preconditions').singleton();

var FIELDS = [
  // Base credentials
  'network',
  'currency',
  'xPrivKey',
  'xPrivKeyEncrypted',
  'xPubKey',
  'requestPrivKey',
  'requestPubKey',
  'publicKeyRing',
  'personalEncryptingKey',
  'mnemonic',
  'mnemonicEncrypted',
  'mnemonicHasPassphrase',
  'derivationStrategy',
  'account',

  // Wallet information
  'walletId',
  'walletName',
  'm',
  'n',
  'walletPrivKey',
  'copayerId',
  'copayerName',
  'addressType',
  'sharedEncryptingKey',

  // Hardware/external wallet
  'hwInfo',
  'externalSource',
  'entropySource',
  'entropySourcePath'
];

var wordsForLang = {
  'en': Mnemonic.Words.ENGLISH,
  'es': Mnemonic.Words.SPANISH,
  'ja': Mnemonic.Words.JAPANESE,
  'zh': Mnemonic.Words.CHINESE,
  'fr': Mnemonic.Words.FRENCH,
  'it': Mnemonic.Words.ITALIAN,
};

var privateKeyEncryptionOpts = {
  iter: 10000
};

function Credentials(opts) {
  opts = opts || {};

  if (opts && opts.network && !lodash.isObject(opts.network)) {
    opts.network = Networks.get(opts.network);
  }

  this.version = '1.0.0';
  this.derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP44;
  this.account = 0;
  this.currency = opts.currency || opts.network.code || Networks.defaultNetwork.code;
  this.network = opts.network.code || Networks.defaultNetwork.code;
};

/**
 * Create from randomly generated number
 *
 * @param {Object} opts
 * @param {String} opts.network - default is defaultNetwork
 */
Credentials.fromRandom = function(opts) {
  opts = opts || {};
  return fromRandom(
    opts.network || Networks.defaultNetwork.code);
};

/**
 * Create using a randomly generated mnemonic
 *
 * @param {Object} opts
 * @param {String} opts.network - default is defaultNetwork
 * @param {String} opts.passphrase
 * @param {Number} opts.language - default 'en'
 * @param {Number} opts.account - default 0
 */
Credentials.fromRandomMnemonic = function(opts) {
  opts = opts || {};
  return fromRandomMnemonic(
    opts.network || Networks.defaultNetwork.code,
    opts.passphrase,
    opts.language || 'en',
    opts.account || 0);
};

/**
 * Create from extended private key
 *
 * @param {String} xPrivKey
 * @param {Number} opts.account - default 0
 * @param {String} opts.derivationStrategy - default 'BIP44'
 */
Credentials.fromExtendedPrivateKey = function(xPrivKey, opts) {
  opts = opts || {};
  return fromExtendedPrivateKey(
    xPrivKey, opts.account || 0,
    opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44,
    opts);
};

/**
 * Create from Mnemonics (language autodetected)
 * Can throw an error if mnemonic is invalid
 *
 * @param {String} BIP39 words
 * @param {Object} opts
 * @param {String} opts.network - default is defaultNetwork
 * @param {String} opts.passphrase
 * @param {Number} opts.account - default 0
 * @param {String} opts.derivationStrategy - default 'BIP44'
 */
Credentials.fromMnemonic = function(words, opts) {
  opts = opts || {};
  return fromMnemonic(
    opts.network || Networks.defaultNetwork.code,
    words,
    opts.passphrase,
    opts.account || 0,
    opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44,
    opts);
};

/**
 * Create from external wallet public key
 *
 * @param {String} xPubKey
 * @param {String} source - A name identifying the source of the xPrivKey (e.g. ledger, TREZOR, ...)
 * @param {String} entropySourceHex - A HEX string containing pseudo-random data, that can be deterministically derived from the xPrivKey, and should not be derived from xPubKey.
 * @param {Object} opts
 * @param {Number} opts.account - default 0
 * @param {String} opts.derivationStrategy - default 'BIP44'
 */
Credentials.fromExtendedPublicKey = function(xPubKey, source, entropySourceHex, opts) {
  opts = opts || {};
  return fromExtendedPublicKey(
    xPubKey,
    source,
    entropySourceHex,
    opts.account || 0,
    opts.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP44);
};

Credentials.fromObj = function(obj) {
  var x = new Credentials();

  lodash.each(FIELDS, function(k) {
    x[k] = obj[k];
  });

  x.derivationStrategy = x.derivationStrategy || Constants.DERIVATION_STRATEGIES.BIP45;
  x.addressType = x.addressType || Constants.SCRIPT_TYPES.P2SH;
  x.account = x.account || 0;

  $.checkState(x.xPrivKey || x.xPubKey || x.xPrivKeyEncrypted, "invalid input");
  return x;
};

Credentials.prototype.toObj = function() {
  var self = this;

  var x = {};
  lodash.each(FIELDS, function(k) {
    x[k] = self[k];
  });
  return x;
};

Credentials.prototype.getBaseAddressDerivationPath = function() {
  checkNetwork(this.network);

  var purpose;
  switch (this.derivationStrategy) {
    case Constants.DERIVATION_STRATEGIES.BIP45:
      return "m/45'";
    case Constants.DERIVATION_STRATEGIES.BIP44:
      purpose = '44';
      break;
    case Constants.DERIVATION_STRATEGIES.BIP48:
      purpose = '48';
      break;
  }

  return "m/" + purpose + "'/" + Networks.get(this.network).coin + "'/" + this.account + "'";
};

Credentials.prototype.getDerivedXPrivKey = function(password) {
  var path = this.getBaseAddressDerivationPath();
  var xPrivKey = new keyLib.HDPrivateKey(this.getKeys(password).xPrivKey, this.network);
  return xPrivKey.deriveChild(path);
};

Credentials.prototype.isPrivKeyEncrypted = function() {
  return (!!this.xPrivKeyEncrypted) && !this.xPrivKey;
};

Credentials.prototype.encryptPrivateKey = function(password, opts) {
  opts = opts || privateKeyEncryptionOpts;

  if (this.xPrivKeyEncrypted)
    throw new Error('Private key already encrypted');

  if (!this.xPrivKey)
    throw new Error('No private key to encrypt');


  this.xPrivKeyEncrypted = sjcl.encrypt(password, this.xPrivKey, opts);
  if (!this.xPrivKeyEncrypted)
    throw new Error('Could not encrypt');

  if (this.mnemonic)
    this.mnemonicEncrypted = sjcl.encrypt(password, this.mnemonic, opts);

  delete this.xPrivKey;
  delete this.mnemonic;
};

Credentials.prototype.decryptPrivateKey = function(password) {
  if (!this.xPrivKeyEncrypted)
    throw new Error('Private key is not encrypted');

  try {
    this.xPrivKey = sjcl.decrypt(password, this.xPrivKeyEncrypted);

    if (this.mnemonicEncrypted) {
      this.mnemonic = sjcl.decrypt(password, this.mnemonicEncrypted);
    }
    delete this.xPrivKeyEncrypted;
    delete this.mnemonicEncrypted;
  } catch (ex) {
    throw new Error('Could not decrypt');
  }
};

Credentials.prototype.getKeys = function(password) {
  var keys = {};

  if (this.isPrivKeyEncrypted()) {
    $.checkArgument(password, 'Private keys are encrypted, a password is needed');
    try {
      keys.xPrivKey = sjcl.decrypt(password, this.xPrivKeyEncrypted);

      if (this.mnemonicEncrypted) {
        keys.mnemonic = sjcl.decrypt(password, this.mnemonicEncrypted);
      }
    } catch (ex) {
      throw new Error('Could not decrypt');
    }
  } else {
    keys.xPrivKey = this.xPrivKey;
    keys.mnemonic = this.mnemonic;
  }
  return keys;
};

/**
 * Checks is password is valid
 * Returns null (keys not encrypted), true or false.
 *
 * @param password
 */
Credentials.prototype.checkPassword = function(password) {
  if (!this.isPrivKeyEncrypted()) return;

  try {
    var keys = this.getKeys(password);
    return !!keys.xPrivKey;
  } catch (e) {
    return false;
  };
};

Credentials.prototype.canSign = function() {
  return (!!this.xPrivKey || !!this.xPrivKeyEncrypted);
};

Credentials.prototype.setNoSign = function() {
  delete this.xPrivKey;
  delete this.xPrivKeyEncrypted;
  delete this.mnemonic;
  delete this.mnemonicEncrypted;
};

Credentials.prototype.hasExternalSource = function() {
  return (typeof this.externalSource == "string");
};

Credentials.prototype.getExternalSourceName = function() {
  return this.externalSource;
};

Credentials.prototype.getMnemonic = function() {
  if (this.mnemonicEncrypted && !this.mnemonic) {
    throw new Error('Credentials are encrypted');
  }
  return this.mnemonic;
};

Credentials.prototype.clearMnemonic = function() {
  delete this.mnemonic;
  delete this.mnemonicEncrypted;
};

/**
 * Wallet information
 */

Credentials.xPubToCopayerId = function(xpub) {
  var hash = sjcl.hash.sha256.hash(xpub);
  return sjcl.codec.hex.fromBits(hash);
};

Credentials.prototype.addWalletPrivateKey = function(walletPrivKey) {
  this.walletPrivKey = walletPrivKey;

  var x = new keyLib.PrivateKey(walletPrivKey);
  x.toAESKey();
  this.sharedEncryptingKey = (new keyLib.PrivateKey(walletPrivKey)).toAESKey();
};

Credentials.prototype.addWalletInfo = function(walletId, walletName, m, n, copayerName) {
  this.walletId = walletId;
  this.walletName = walletName;
  this.m = m;
  this.n = n;

  this.copayerId = Credentials.xPubToCopayerId(this.xPubKey);

  if (copayerName) {
    this.copayerName = copayerName;
  }

  if (this.derivationStrategy == 'BIP44' && n == 1) {
    this.addressType = Constants.SCRIPT_TYPES.P2PKH;
  } else {
    this.addressType = Constants.SCRIPT_TYPES.P2SH;
  }

  // Use m/48' for multisig hardware wallets
  if (!this.xPrivKey && this.externalSource && n > 1) {
    this.derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP48;
  }

  if (n == 1) {
    this.addPublicKeyRing([{
      xPubKey: this.xPubKey,
      requestPubKey: this.requestPubKey,
    }]);
  }
};

Credentials.prototype.hasWalletInfo = function() {
  return !!this.walletId;
};

Credentials.prototype.isComplete = function() {
  if (!this.m || !this.n || !this.publicKeyRing || this.publicKeyRing.length != this.n) {
    return false;
  }
  return true;
};

Credentials.prototype.addPublicKeyRing = function(publicKeyRing) {
  this.publicKeyRing = lodash.clone(publicKeyRing);
};

Credentials.prototype.getCopayerHash = function() {
  return [this.copayerName, this.xPubKey, this.requestPubKey].join('|');
};

/**
 * Validate key derivation
 *
 * @param {Object} opts
 * @param {String} opts.passphrase
 * @param {String} opts.skipDeviceValidation
 */
/* TODO: this needs to be made extensible for any coin

Credentials.prototype.validateKeyDerivation = function(opts, cb) {
  var self = this;
  opts = opts || {};
  var c = self.credentials;

  function testMessageSigning(xpriv, xpub) {
    var nonHardenedPath = 'm/0/0';
    var message = 'Lorem ipsum dolor sit amet, ne amet urbanitas percipitur vim, libris disputando his ne, et facer \
      suavitate qui. Ei quidam laoreet sea. Cu pro dico aliquip gubergren, in mundi postea usu. Ad labitur posidonium \
      interesset duo, est et doctus molestie adipiscing.';

    var priv = xpriv.deriveChild(nonHardenedPath).privateKey;
    var signature = Utils.signMessage(message, priv);
    var pub = xpub.deriveChild(nonHardenedPath).publicKey;
    return Utils.verifyMessage(message, signature, pub);
  };

  function testHardcodedKeys() {
    var words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    var xpriv = Mnemonic(words).toHDPrivateKey();

    if (xpriv.toString() != 'xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu') {
      return false;
    }

    xpriv = xpriv.deriveChild("m/44'/0'/0'");
    if (xpriv.toString() != 'xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb') {
      return false;
    }

    var xpub = keyLib.HDPublicKey.fromString('xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj');
    return testMessageSigning(xpriv, xpub);
  };

  function testLiveKeys() {
    var words;
    try {
      words = c.getMnemonic();
    } catch (ex) {}

    var xpriv;
    if (words && (!c.mnemonicHasPassphrase || opts.passphrase)) {
      var m = new Mnemonic(words);
      xpriv = m.toHDPrivateKey(opts.passphrase, c.network);
    }
    if (!xpriv) {
      xpriv = new keyLib.HDPrivateKey(c.xPrivKey);
    }
    xpriv = xpriv.deriveChild(c.getBaseAddressDerivationPath());
    var xpub = new keyLib.HDPublicKey(c.xPubKey);

    return testMessageSigning(xpriv, xpub);
  };

  var hardcodedOk = true;
  if (!_deviceValidated && !opts.skipDeviceValidation) {
    hardcodedOk = testHardcodedKeys();
    _deviceValidated = true;
  }

  var liveOk = (c.canSign() && !c.isPrivKeyEncrypted()) ? testLiveKeys() : true;

  self.keyDerivationOk = hardcodedOk && liveOk;

  return cb(null, self.keyDerivationOk);
};
*/

/**
 * Private functions
 */

/**
 * Create xprv key credentials using a randomly generated seed (no mnemonic exists).
 */
function fromRandom(network) {
  checkNetwork(network);

  var x = new Credentials({
    network: network
  });

  x.xPrivKey = (new keyLib.HDPrivateKey(network)).toString();
  expand(x);
  return x;
};

/**
 * Create xprv key credentials by creating a new, randomly generated mnemonic.
 */
function fromRandomMnemonic(network, passphrase, language, account, opts) {
  checkNetwork(network);
  if (!wordsForLang[language]) throw new Error('Unsupported language');
  $.shouldBeNumber(account);

  opts = opts || {};

  var m = new Mnemonic(wordsForLang[language]);
  while (!Mnemonic.isValid(m.toString())) {
    m = new Mnemonic(wordsForLang[language])
  };
  var x = new Credentials({
    network: network
  });

//  x.network = network;
  x.account = account;
  x.xPrivKey = m.toHDPrivateKey(passphrase, network).toString();
  x.mnemonic = m.phrase;
  x.mnemonicHasPassphrase = !!passphrase;
  expand(x);

  return x;
};

/**
 * Create xprv key credentials using the specified extended private key (no key is generated, no mnemonic exists).
 */
function fromExtendedPrivateKey(xPrivKey, account, derivationStrategy, opts) {
  $.shouldBeNumber(account);
  $.checkArgument(lodash.includes(lodash.values(Constants.DERIVATION_STRATEGIES), derivationStrategy));

  opts = opts || {};
  var data = Base58Check.decode(xPrivKey);
  var version = BufferUtil.integerFromBuffer(data.slice(0, 4));
  var network = Networks.get(version, 'version.xprivkey');

  var x = new Credentials({
    network: network
  });

  x.xPrivKey = xPrivKey;
  x.account = account;
  x.derivationStrategy = derivationStrategy;

  if (opts.walletPrivKey) {
    x.addWalletPrivateKey(opts.walletPrivKey);
  }

  expand(x);
  return x;
};

/**
 * Create xprv key credentials using a specified mnemonic.
 * Note that mnemonic / passphrase is NOT stored.
 */
function fromMnemonic(network, words, passphrase, account, derivationStrategy, opts) {
  checkNetwork(network);
  $.shouldBeNumber(account);
  $.checkArgument(lodash.includes(lodash.values(Constants.DERIVATION_STRATEGIES), derivationStrategy));

  opts = opts || {};

  var m = new Mnemonic(words);
  var x = new Credentials({
    network: network
  });
  x.xPrivKey = m.toHDPrivateKey(passphrase, network).toString();
  x.mnemonic = words;
  x.mnemonicHasPassphrase = !!passphrase;
  x.account = account;
  x.derivationStrategy = derivationStrategy;
  x.entropySourcePath = opts.entropySourcePath;

  if (opts.walletPrivKey) {
    x.addWalletPrivateKey(opts.walletPrivKey);
  }

  expand(x);
  return x;
};
/**
 * Create credentials using the specified extended public key (no xprv key is generated, no mnemonic exists).
 * Used for creating credentials including a private key for requesting services from an external source, e.g., hardware wallet.
 *
 * xPrivKey -> m/44'/network'/account' -> Base Address Key
 * so, xPubKey is PublicKeyHD(xPrivKey.deriveChild("m/44'/network'/account'")).
 *
 * For external sources, this derivation should be done before call fromExtendedPublicKey.
 *
 * entropySource should be a HEX string containing pseudo-random data, that can be deterministically derived from
 * the xPrivKey, and should not be derived from xPubKey.
 */
function fromExtendedPublicKey(xPubKey, source, entropySourceHex, account, derivationStrategy, opts) {
  $.checkArgument(entropySourceHex);
  $.shouldBeNumber(account);
  $.checkArgument(lodash.includes(lodash.values(Constants.DERIVATION_STRATEGIES), derivationStrategy));

  opts = opts || {};

  var entropyBuffer = new Buffer(entropySourceHex, 'hex');
  // Require at least 112 bits of entropy.
  $.checkArgument(entropyBuffer.length >= 14, 'At least 112 bits of entropy are needed')

  var data = Base58Check.decode(xPubKey);
  var version = BufferUtil.integerFromBuffer(data.slice(0, 4));
  var network = Networks.get(version, 'version.xpubkey');

  var x = new Credentials({
    network: network
  });

  x.xPubKey = xPubKey;
  x.entropySource = Hash.sha256sha256(entropyBuffer).toString('hex');
  x.account = account;
  x.derivationStrategy = derivationStrategy;
  x.externalSource = source;
  expand(x);

  return x;
};

function checkNetwork(network) {
  if (!Networks.get(network)) {
    throw new Error('Invalid network');
  }
};

/*
xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx

rprv7v2RjrNn6xnRvak9VNuMonLgxXnysMPL1zBTxcayEMQi1B85utF4GJQJ5u3xBzyQum9XGApfNJKDRxJJTWVSV9x8fiQY4vep7jBF2VmcRm2
7v2RjrNn6xnRvak9VNuMonLgxXnysMPL1zBTxcayEMQi1B85utF4GJQJ5u3xBzyQum9XGApfNJKDRxJJTWVSV9x8fiQY4vep7jBF2VmcRm2
         1         2         3         4         5         6         7        8         9         0         1
*/
// Get network from extended private key or extended public key.
function getNetworkFromExtendedKey(xKey) {
  $.checkArgument(xKey && lodash.isString(xKey));

  var data = Base58Check.decode(xKey);
  var version = BufferUtil.integerFromBuffer(data.slice(0, 4));
  var n = Networks.get(version, 'version.xprivkey');
  return n.code;
};

function hashFromEntropy(entropySource, prefix, length) {
  $.checkState(prefix);
  var b = new Buffer(entropySource, 'hex');
  var b2 = Hash.sha256hmac(b, new Buffer(prefix));
  return b2.slice(0, length);
};

function expand(credentials) {
  $.checkState(credentials.xPrivKey || (credentials.xPubKey && credentials.entropySource));

  var network = getNetworkFromExtendedKey(credentials.xPrivKey || credentials.xPubKey);
  if (credentials.network) {
    $.checkState(credentials.network == network);
  } else {
    credentials.network = network;
  }

  if (credentials.xPrivKey) {
    var xPrivKey = new keyLib.HDPrivateKey.fromString(credentials.xPrivKey);
    var derivedXPrivKey = xPrivKey.deriveChild(credentials.getBaseAddressDerivationPath());

    // This is the xPubKey shared with the server.
    credentials.xPubKey = derivedXPrivKey.hdPublicKey.toString();
  }

  // Requests keys from mnemonics, but using a xPubkey.
  // This is only used when importing mnemonics FROM a hardware wallet in which xprv was not available when the wallet was created.
  if (credentials.entropySourcePath) {
    var seed = xPrivKey.deriveChild(credentials.entropySourcePath).publicKey.toBuffer();
    credentials.entropySource = Hash.sha256sha256(seed).toString('hex');
  }

  if (credentials.entropySource) {
    // Request keys from entropy (hardware wallets).
    var seed = hashFromEntropy(credentials.entropySource, 'reqPrivKey', 32);
    var privKey = new keyLib.PrivateKey(seed.toString('hex'), Credentials.network);
    credentials.requestPrivKey = privKey.toString();
    credentials.requestPubKey = privKey.toPublicKey().toString();

  } else {
    // Request keys derived from xPriv.
    var requestDerivation = xPrivKey.deriveChild(Constants.PATHS.REQUEST_KEY);
    credentials.requestPrivKey = requestDerivation.privateKey.toString();

    var pubKey = requestDerivation.publicKey;
    credentials.requestPubKey = pubKey.toString();
    credentials.entropySource = Hash.sha256(requestDerivation.privateKey.toBuffer()).toString('hex');
  }

  credentials.personalEncryptingKey = hashFromEntropy(credentials.entropySource, 'personalKey', 16).toString('base64');

  credentials.publicKeyRing = [{
    xPubKey: credentials.xPubKey,
    requestPubKey: credentials.requestPubKey,
  }];
};

module.exports = Credentials;
