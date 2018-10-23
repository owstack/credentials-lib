# Wallet Seed
Creates a wallet credentials object using various kinds of input source data.

### Credentials object

Sample credentials object.

```javascript
credentials = {
  account: 0,
  copayerId: "db8079078298b0fe2edb388d328e018fc08e17bc9940e2a96a59b4c9893a1849",
  currency: "btc",
  derivationStrategy: "BIP44",
  entropySource: "8545a6cfd0e141d1c84da5ddfa647c294350aa42963b88d23e3cc4a921c685de",
  mnemonic: "before cotton december donate cake extra garbage cave sign globe yellow keen",
  mnemonicHasPassphrase: false,
  network: "BTC",
  personalEncryptingKey: "G4jcttPbEhyYB/Gix4ccNQ==",
  publicKeyRing: [{
    xPubKey: "xpub6Bqg2SgLRmjVzBU2rSqMAoauKvGEza2Eq6b38JepckqQ7afRBaeu5si3CK3SyH9ffwjeJQL7KzfaXQj5qze7TQivfjqSSYafTxEr1bGjiUA",
    requestPubKey: "0344b822d8b27730553675f45f58c5bb540791c29805902ffa3216000ede0060f5",
	}],
  requestPrivKey: "bbe5fcfa904e5e4d174e359e72f00eb425872ef9d928d4b0961138fb23a25509",
  requestPubKey: "0344b822d8b27730553675f45f58c5bb540791c29805902ffa3216000ede0060f5",
  version: "1.0.0",
  xPrivKey: "xprv9s21ZrQH143K4Qb39iUDPfZm7i1aeaQDNs5yFNjBxK7tnYsVVquFBjTzGzZisqg6j8T1KJy8Syx3tj1Kksff9e8rm3H7PY6HzhEB5qyuxCz",
  xPubKey: "xpub6Bqg2SgLRmjVzBU2rSqMAoauKvGEza2Eq6b38JepckqQ7afRBaeu5si3CK3SyH9ffwjeJQL7KzfaXQj5qze7TQivfjqSSYafTxEr1bGjiUA"
}
```

### Seed from Random

seedFromRandom(opts, opts.network)

**Parameters**

**opts**: `Object`, Seed from random

**opts.network**: `String`, one of the [supported networks](networks.md/), default 'BTC'

```javascript
var wcLib = require('@owstack/wallet-credentials-lib');

var credentials = wcLib.seedFromRandom({
	network: 'BTC'
});
```

### Seed from Random with specified mnemonic

seedFromRandomWithMnemonic(opts, opts.network, opts.passphrase, opts.language, opts.account)

**Parameters**

**opts**: `Object`, Seed from random with mnemonic

**opts.network**: `String`, one of the [supported networks](networks.md/), default 'BTC'

**opts.passphrase**: `String`, Seed from random with mnemonic

**opts.language**: `Number`, default 'en'

**opts.account**: `Number`, default 0

```javascript
var wcLib = require('@owstack/wallet-credentials-lib');

var credentials = wcLib.seedFromRandomWithMnemonic({
	network: 'BTC',
	passphrase: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon',
	account: 0
});
```

### Seed from Extended Private Key

seedFromExtendedPrivateKey(xPrivKey, opts.account, opts.derivationStrategy)

**Parameters**

**xPrivKey**: `String`, Seed from extended private key

**opts.account**: `Number`, default 0

**opts.derivationStrategy**: `String`, default 'BIP44'

```javascript
var wcLib = require('@owstack/wallet-credentials-lib');

var credentials = wcLib.seedFromExtendedPrivateKey('xprv...');
```

### Seed from Mnemonic

seedFromMnemonic(BIP39, opts)

**Parameters**

**BIP39**: `String`, words

**opts**: `Object`, Seed from Mnemonics (language autodetected)
Can throw an error if mnemonic is invalid

**opts.network**: `String`, one of the [supported networks](networks.md/), default 'BTC'

**opts.passphrase**: `String`, Seed from Mnemonics (language autodetected)
Can throw an error if mnemonic is invalid

**opts.account**: `Number`, default 0

**opts.derivationStrategy**: `String`, default 'BIP44'

```javascript
var wcLib = require('@owstack/wallet-credentials-lib');

var credentials = wcLib.seedFromMnemonic('abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon');
```

### Seed from External Wallet Public Key

seedFromExtendedPublicKey(xPubKey, source, entropySourceHex, opts)

**Parameters**

**xPubKey**: `String`, Seed from external wallet public key

**source**: `String`, A name identifying the source of the xPrivKey (e.g. ledger, TREZOR, ...)

**entropySourceHex**: `String`, A HEX string containing pseudo-random data, that can be deterministically derived from the xPrivKey, and should not be derived from xPubKey.

**opts**: `Object`, Seed from external wallet public key

**opts.account**: `Number`, default 0

**opts.derivationStrategy**: `String`, default 'BIP44'

```javascript
var wcLib = require('@owstack/wallet-credentials-lib');

var entropySource = getFromHwWalletService(); // Received from a hardware wallet service.
var credentials = wcLib.seedFromExtendedPublicKey('xpub...', 'ledger', entropySource, {
  account: 0,
  derivationStrategy: 'BIP44'
});
```
