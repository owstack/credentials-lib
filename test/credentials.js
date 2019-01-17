'use strict';

var chai = chai || require('chai');
var sinon = sinon || require('sinon');
var should = chai.should();

var owsCommon = require('@owstack/ows-common');
var Constants = owsCommon.Constants;
var Credentials = require('../lib/credentials');
var lodash = owsCommon.deps.lodash;

// Setup some networks for tests.
require('./data/networks');

describe('Credentials', function() {
  describe('#create', function() {
    it('Should create', function() {
      var c = Credentials.fromRandom({networkName: 'btc'});
      should.exist(c.xPrivKey);
    });

    it('Should create random credentials', function() {
      var all = {};
      for (var i = 0; i < 10; i++) {
        var c = Credentials.fromRandom({networkName: 'btc'});
        var exist = all[c.xPrivKey];
        should.not.exist(exist);
        all[c.xPrivKey] = 1;
      }
    });
  });

  describe('#getBaseAddressDerivationPath', function() {
    it('should return path for BTC network', function() {
      var c = Credentials.fromRandom({networkName: 'btc'});
      var path = c.getBaseAddressDerivationPath();
      path.should.equal("m/44'/0'/0'");
    });

    it('should return path for BTC network account 2', function() {
      var c = Credentials.fromRandom({networkName: 'btc'});
      c.account = 2;
      var path = c.getBaseAddressDerivationPath();
      path.should.equal("m/44'/0'/2'");
    });

    it('should return path for BIP45', function() {
      var c = Credentials.fromRandom({networkName: 'btc'});
      c.derivationStrategy = Constants.DERIVATION_STRATEGIES.BIP45;
      var path = c.getBaseAddressDerivationPath();
      path.should.equal("m/45'");
    });
  });

  describe('#getDerivedXPrivKey', function() {
    it('should derive extended private key from master BTC network', function() {
      var c = Credentials.fromExtendedPrivateKey('xprv9s21ZrQH143K3zLpjtB4J4yrRfDTEfbrMa9vLZaTAv5BzASwBmA16mdBmZKpMLssw1AzTnm31HAD2pk2bsnZ9dccxaLD48mRdhtw82XoiBi', {
        account: 0,
        derivationStrategy: 'BIP44'
      });
      var xpk = c.getDerivedXPrivKey().toString();
      xpk.should.equal('xprv9xud2WztGSSBPDPDL9RQ3rG3vucRA4BmEnfAdP76bTqtkGCK8VzWjevLw9LsdqwH1PEWiwcjymf1T2FLp12XjwjuCRvcSBJvxDgv1BDTbWY');
    });

    it('should derive extended private key from master BIP48 BTC network', function() {
      var c = Credentials.fromExtendedPrivateKey('xprv9s21ZrQH143K3zLpjtB4J4yrRfDTEfbrMa9vLZaTAv5BzASwBmA16mdBmZKpMLssw1AzTnm31HAD2pk2bsnZ9dccxaLD48mRdhtw82XoiBi', {
        account: 0,
        derivationStrategy: 'BIP48'
      });
      var xpk = c.getDerivedXPrivKey().toString();
      xpk.should.equal('xprv9yaGCLKPS2ovEGw987MZr4DCkfZHGh518ndVk3Jb6eiUdPwCQu7nYru59WoNkTEQvmhnv5sPbYxeuee5k8QASWRnGV2iFX4RmKXEQse8KnQ');
    });

    it('should derive extended private key from master BTC network (BIP45)', function() {
      var c = Credentials.fromExtendedPrivateKey('xprv9s21ZrQH143K3zLpjtB4J4yrRfDTEfbrMa9vLZaTAv5BzASwBmA16mdBmZKpMLssw1AzTnm31HAD2pk2bsnZ9dccxaLD48mRdhtw82XoiBi', {
        account: 0,
        derivationStrategy: 'BIP45'
      });
      var xpk = c.getDerivedXPrivKey().toString();
      xpk.should.equal('xprv9vDaAbbvT8LHKr8v5A2JeFJrnbQk6ZrMDGWuiv2vZgSyugeV4RE7Z9QjBNYsdafdhwEGb6Y48DRrXFVKvYRAub9ExzcmJHt6Js6ybJCSssm');
    });

    it('should set addressType & BIP45', function() {
      var c = Credentials.fromExtendedPrivateKey('xprv9s21ZrQH143K3zLpjtB4J4yrRfDTEfbrMa9vLZaTAv5BzASwBmA16mdBmZKpMLssw1AzTnm31HAD2pk2bsnZ9dccxaLD48mRdhtw82XoiBi', {
        account: 8,
        derivationStrategy: 'BIP45'
      });
      c.copayerName = 'juan';
      c.account.should.equal(8);
      should.exist(c.copayerId);
    });

    it('should derive child', function() {
      var c = Credentials.fromExtendedPrivateKey('xprv9s21ZrQH143K3zLpjtB4J4yrRfDTEfbrMa9vLZaTAv5BzASwBmA16mdBmZKpMLssw1AzTnm31HAD2pk2bsnZ9dccxaLD48mRdhtw82XoiBi', {
        account: 0,
        derivationStrategy: 'BIP44'
      });
      var xpk = c.getDerivedXPrivKey().toString();
      xpk.should.equal('xprv9xud2WztGSSBPDPDL9RQ3rG3vucRA4BmEnfAdP76bTqtkGCK8VzWjevLw9LsdqwH1PEWiwcjymf1T2FLp12XjwjuCRvcSBJvxDgv1BDTbWY');
    });
  });

  describe('#fromExtendedPrivateKey', function() {
    it('Should create credentials from seed', function() {
      var xPriv = 'xprv9s21ZrQH143K2TjT3rF4m5AJcMvCetfQbVjFEx1Rped8qzcMJwbqxv21k3ftL69z7n3gqvvHthkdzbW14gxEFDYQdrRQMub3XdkJyt3GGGc';
      var c = Credentials.fromExtendedPrivateKey(xPriv, {
        account: 0,
        derivationStrategy: 'BIP44'
      });

      c.xPrivKey.should.equal('xprv9s21ZrQH143K2TjT3rF4m5AJcMvCetfQbVjFEx1Rped8qzcMJwbqxv21k3ftL69z7n3gqvvHthkdzbW14gxEFDYQdrRQMub3XdkJyt3GGGc');
      c.xPubKey.should.equal('xpub6DUean44k773kxbUq8QpSmAPFaNCpk5AzrxbFRAMsNCZBGD15XQVnRJCgNd8GtJVmDyDZh89NPZz1XPQeX5w6bAdLGfSTUuPDEQwBgKxfh1');
      c.networkName.should.equal('btc');
      c.currency.should.equal('BTC');
      c.personalEncryptingKey.should.equal('M4MTmfRZaTtX6izAAxTpJg==');
      should.not.exist(c.privKey);
    });

    it('Should create credentials from seed and privateKey', function() {
      var xPriv = 'xprv9s21ZrQH143K2TjT3rF4m5AJcMvCetfQbVjFEx1Rped8qzcMJwbqxv21k3ftL69z7n3gqvvHthkdzbW14gxEFDYQdrRQMub3XdkJyt3GGGc';
      var wKey = 'a28840e18650b1de8cb83bcd2213672a728be38a63e70680b0c2be9c452e2d4d';
      var c = Credentials.fromExtendedPrivateKey(xPriv, {
        account: 0,
        derivationStrategy: 'BIP44',
        privKey: 'a28840e18650b1de8cb83bcd2213672a728be38a63e70680b0c2be9c452e2d4d'
      });

      c.xPrivKey.should.equal('xprv9s21ZrQH143K2TjT3rF4m5AJcMvCetfQbVjFEx1Rped8qzcMJwbqxv21k3ftL69z7n3gqvvHthkdzbW14gxEFDYQdrRQMub3XdkJyt3GGGc');
      c.privKey.should.equal(wKey);
    });

    describe('Derivation', function() {
      it('Should create base address derivation key', function() {
        var xPriv = 'xprv9s21ZrQH143K4HHBKb6APEoa5i58fxeFWP1x5AGMfr6zXB3A6Hjt7f9LrPXp9P7CiTCA3Hk66cS4g8enUHWpYHpNhtufxSrSpcbaQyVX163';
        var c = Credentials.fromExtendedPrivateKey(xPriv, {
        account: 0,
        derivationStrategy: 'BIP44'
      });
        c.xPubKey.should.equal('xpub6CUtFEwZKBEyX6xF4ECdJdfRBBo69ufVgmRpy7oqzWJBSadSZ3vaqvCPNFsarga4UWcgTuoDQL7ZnpgWkUVUAX3oc7ej8qfLEuhMALGvFwX');
      });

      it('Should create request key', function() {
        var xPriv = 'xprv9s21ZrQH143K3xMCR1BNaUrTuh1XJnsj8KjEL5VpQty3NY8ufgbR8SjZS8B4offHq6Jj5WhgFpM2dcYxeqLLCuj1wgMnSfmZuPUtGk8rWT7';
        var c = Credentials.fromExtendedPrivateKey(xPriv, {
          account: 0,
          derivationStrategy: 'BIP44'
        });
        c.requestPrivKey.should.equal('559371263eb0b2fd9cd2aa773ca5fea69ed1f9d9bdb8a094db321f02e9d53cec');
      });

    });

  });

  describe('#fromMnemonic', function() {
    it('Should create credentials from mnemonic BIP44', function() {
      var words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      var c = Credentials.fromMnemonic(words, {
        networkName: 'btc',
        passphrase: '',
        account: 0,
        derivationStrategy: 'BIP44'
      });
      c.xPrivKey.should.equal('xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu');
      c.networkName.should.equal('btc');
      c.currency.should.equal('BTC');
      c.account.should.equal(0);
      c.derivationStrategy.should.equal('BIP44');
      c.xPubKey.should.equal('xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj');
      c.getBaseAddressDerivationPath().should.equal("m/44'/0'/0'");
    });

    it('Should create credentials from mnemonic BIP48', function() {
      var words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      var c = Credentials.fromMnemonic(words, {
        networkName: 'btc',
        passphrase: '',
        account: 0,
        derivationStrategy: 'BIP48'
      });
      c.xPrivKey.should.equal('xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu');
      c.networkName.should.equal('btc');
      c.currency.should.equal('BTC');
      c.account.should.equal(0);
      c.derivationStrategy.should.equal('BIP48');
      c.xPubKey.should.equal('xpub6CKZtUaK1YHpQbg6CLaGRmsMKLQB1iKzsvmxtyHD6X7gzLqCB2VNZYd1XCxrccQnE8hhDxtYbR1Sakkvisy2J4CcTxWeeGjmkasCoNS9vZm');
      c.getBaseAddressDerivationPath().should.equal("m/48'/0'/0'");
    });

    it('Should create credentials from mnemonic account 1', function() {
      var words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      var c = Credentials.fromMnemonic(words, {
        networkName: 'btc',
        passphrase: '',
        account: 1,
        derivationStrategy: 'BIP44'
      });
      c.xPrivKey.should.equal('xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu');
      c.account.should.equal(1);
      c.xPubKey.should.equal('xpub6BosfCnifzxcJJ1wYuntGJfF2zPJkDeG9ELNHcKNjezuea4tumswN9sH1psMdSVqCMoJC21Bv8usSeqSP4Sp1tLzW7aY59fGn9GCYzx5UTo');
      c.getBaseAddressDerivationPath().should.equal("m/44'/0'/1'");
    });

    it('Should create credentials from mnemonic with undefined/null passphrase', function() {
      var words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      var c = Credentials.fromMnemonic(words, {
        networkName: 'btc',
        passphrase: undefined,
        account: 0,
        derivationStrategy: 'BIP44'
      });
      c.xPrivKey.should.equal('xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu');
      c = Credentials.fromMnemonic(words, {
        networkName: 'btc',
        passphrase: null,
        account: 0,
        derivationStrategy: 'BIP44'
      });
      c.xPrivKey.should.equal('xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu');
    });

    it('Should create credentials from mnemonic and passphrase', function() {
      var words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      var c = Credentials.fromMnemonic(words, {
        networkName: 'btc',
        passphrase: 'húngaro',
        account: 0,
        derivationStrategy: 'BIP44'
      });
      c.xPrivKey.should.equal('xprv9s21ZrQH143K2LkGEPHqW8w5vMJ3giizin94rFpSM5Ys5KhDaP7Hde3rEuzC7VpZDtNX643bJdvhHnkbhKMNmLx3Yi6H8WEsHBBox3qbpqq');
    });

    it('Should create credentials from mnemonic (ES)', function() {
      var words = 'afirmar diseño hielo fideo etapa ogro cambio fideo toalla pomelo número buscar';
      var c = Credentials.fromMnemonic(words, {
        networkName: 'btc',
        passphrase: '',
        account: 0,
        derivationStrategy: 'BIP44'
      });
      c.xPrivKey.should.equal('xprv9s21ZrQH143K3H3WtXCn9nHtpi7Fz1ZE9VJErWErhrGL4hV1cApFVo3t4aANoPF7ufcLLWqN168izu3xGQdLaGxXG2qYZF8wWQGNWnuSSon');
      c.networkName.should.equal('btc');
      c.currency.should.equal('BTC');
    });

    describe('Derivation', function() {
      it('Should create base address derivation key from mnemonic', function() {
        var words = "shoulder sphere pull seven top much black copy labor dress depth unit";
        var c = Credentials.fromMnemonic(words, {
        networkName: 'btc',
        passphrase: '',
        account: 0,
        derivationStrategy: 'BIP44'
      });
        c.xPrivKey.should.equal('xprv9s21ZrQH143K3WoNK8dVjQJpcXhqfwyuBTpuZdc1ZVa9yWW2i7TmM4TLyfPrSKXctQuLgbg3U1WJmodK9yWM26JWeuh2vhT6bmsPPie688n');
        c.xPubKey.should.equal('xpub6DVMaW3r1CcZcsUazSHspjRfZZJzZG3N7GRL4DciY54Z8M4KmRSDrq2hd75VzxKZDXPu4EKiAwCGwiXMxec2pq6oVgtZYxQHSrgtxksWehx');
      });

      it('Should create request key from mnemonic', function() {
        var words = "pool stomach bridge series powder mammal betray slogan pass roast neglect reunion";
        var c = Credentials.fromMnemonic(words, {
        networkName: 'btc',
        passphrase: '',
        account: 0,
        derivationStrategy: 'BIP44'
      });
        c.xPrivKey.should.equal('xprv9s21ZrQH143K3ZMudFRXpEwftifDuJkjLKnCtk26pXhxQuK8bCnytJuUTGkfvaibnCxPQQ9xToUtDAZkJqjm3W62GBXXr7JwhiAz1XWgTUJ');
        c.requestPrivKey.should.equal('7582efa9b71aefa831823592d753704cba9648b810b14b77ee078dfe8b730157');
      });
    });
  });

  describe('#fromRandomMnemonic', function() {
    it('Should create credentials with mnemonic', function() {
      var c = Credentials.fromRandomMnemonic({
        networkName: 'btc',
        passphrase: '',
        language: 'en',
        account: 0
      });
      should.exist(c.mnemonic);
      c.mnemonic.split(' ').length.should.equal(12);
      c.networkName.should.equal('btc');
      c.currency.should.equal('BTC');
      c.account.should.equal(0);
    });

    it('should assume derivation compliance on new credentials', function() {
      var c = Credentials.fromRandomMnemonic({
        networkName: 'btc',
        passphrase: '',
        language: 'en',
        account: 0
      });
      var xPrivKey = c.getDerivedXPrivKey();
      should.exist(xPrivKey);
    });

    it('Should return and clear mnemonic', function() {
      var c = Credentials.fromRandomMnemonic({
        networkName: 'btc',
        passphrase: '',
        language: 'en',
        account: 0
      });
      should.exist(c.mnemonic);
      c.getMnemonic().split(' ').length.should.equal(12);
      c.clearMnemonic();
      should.not.exist(c.getMnemonic());
    });
  });

  describe('#fromRandomMnemonic #fromMnemonic roundtrip', function() {
    lodash.each(['en', 'es', 'ja', 'zh', 'fr'], function(lang) {
      it('Should verify roundtrip create/from with ' + lang + '/passphrase', function() {
        var c = Credentials.fromRandomMnemonic({
          networkName: 'btc',
          passphrase: 'holamundo',
          language: lang,
          account: 0
        });
        should.exist(c.mnemonic);
        var words = c.mnemonic;
        var xPriv = c.xPrivKey;
        var path = c.getBaseAddressDerivationPath();

        var c2 = Credentials.fromMnemonic(words, {
          networkName: 'btc',
          passphrase: 'holamundo',
          account: 0,
          derivationStrategy: 'BIP44'
        });
        should.exist(c2.mnemonic);
        words.should.be.equal(c2.mnemonic);
        c2.xPrivKey.should.equal(c.xPrivKey);
        c2.networkName.should.equal(c.networkName);
        c2.getBaseAddressDerivationPath().should.equal(path);
      });
    });

    it('Should fail roundtrip create/from with ES/passphrase with wrong passphrase', function() {
      var c = Credentials.fromRandomMnemonic({
          networkName: 'btc',
          passphrase: 'holamundo',
          language: 'es',
          account: 0
        });
      should.exist(c.mnemonic);
      var words = c.mnemonic;
      var xPriv = c.xPrivKey;
      var path = c.getBaseAddressDerivationPath();

      var c2 = Credentials.fromMnemonic(words, {
          networkName: 'btc',
          passphrase: 'chaumundo',
          account: 0,
          derivationStrategy: 'BIP44'
        });
      c2.networkName.should.equal(c.networkName);
      c2.getBaseAddressDerivationPath().should.equal(path);
      c2.xPrivKey.should.not.equal(c.xPrivKey);
    });
  });

  describe('Private key encryption', function() {
    describe('#encryptPrivateKey', function() {
      it('should encrypt private key and remove cleartext', function() {
        var c = Credentials.fromRandomMnemonic({
          networkName: 'btc',
          passphrase: '',
          language: 'en',
          account: 0
        });
        c.encryptPrivateKey('password');
        c.isPrivKeyEncrypted().should.be.true;
        should.exist(c.xPrivKeyEncrypted);
        should.exist(c.mnemonicEncrypted);
        should.not.exist(c.xPrivKey);
        should.not.exist(c.mnemonic);
      });

      it('should fail to encrypt private key if already encrypted', function() {
        var c = Credentials.fromRandom({networkName: 'btc'});
        c.encryptPrivateKey('password');
        var err;
        try {
          c.encryptPrivateKey('password');
        } catch (ex) {
          err = ex;
        }
        should.exist(err);
      });
    });

    describe('#decryptPrivateKey', function() {
      it('should decrypt private key', function() {
        var c = Credentials.fromRandomMnemonic({
          networkName: 'btc',
          passphrase: '',
          language: 'en',
          account: 0
        });
        c.encryptPrivateKey('password');
        c.isPrivKeyEncrypted().should.be.true;
        c.decryptPrivateKey('password');
        c.isPrivKeyEncrypted().should.be.false;
        should.exist(c.xPrivKey);
        should.exist(c.mnemonic);
        should.not.exist(c.xPrivKeyEncrypted);
        should.not.exist(c.mnemonicEncrypted);
      });

      it('should fail to decrypt private key with wrong password', function() {
        var c = Credentials.fromRandomMnemonic({
          networkName: 'btc',
          passphrase: '',
          language: 'en',
          account: 0
        });
        c.encryptPrivateKey('password');

        var err;
        try {
          c.decryptPrivateKey('wrong');
        } catch (ex) {
          err = ex;
        }
        should.exist(err);
        c.isPrivKeyEncrypted().should.be.true;
        should.exist(c.mnemonicEncrypted);
        should.not.exist(c.mnemonic);
      });

      it('should fail to decrypt private key when not encrypted', function() {
        var c = Credentials.fromRandom({networkName: 'btc'});

        var err;
        try {
          c.decryptPrivateKey('password');
        } catch (ex) {
          err = ex;
        }
        should.exist(err);
        c.isPrivKeyEncrypted().should.be.false;
      });
    });

    describe('#getKeys', function() {
      it('should get keys regardless of encryption', function() {
        var c = Credentials.fromRandomMnemonic({
          networkName: 'btc',
          passphrase: '',
          language: 'en',
          account: 0
        });
        var keys = c.getKeys();
        should.exist(keys);
        should.exist(keys.xPrivKey);
        should.exist(keys.mnemonic);
        keys.xPrivKey.should.equal(c.xPrivKey);
        keys.mnemonic.should.equal(c.mnemonic);

        c.encryptPrivateKey('password');
        c.isPrivKeyEncrypted().should.be.true;
        var keys2 = c.getKeys('password');
        should.exist(keys2);
        keys2.should.deep.equal(keys);

        c.decryptPrivateKey('password');
        c.isPrivKeyEncrypted().should.be.false;
        var keys3 = c.getKeys();
        should.exist(keys3);
        keys3.should.deep.equal(keys);
      });

      it('should get derived keys regardless of encryption', function() {
        var c = Credentials.fromRandomMnemonic({
          networkName: 'btc',
          passphrase: '',
          language: 'en',
          account: 0
        });
        var xPrivKey = c.getDerivedXPrivKey();
        should.exist(xPrivKey);

        c.encryptPrivateKey('password');
        c.isPrivKeyEncrypted().should.be.true;
        var xPrivKey2 = c.getDerivedXPrivKey('password');
        should.exist(xPrivKey2);

        xPrivKey2.toString('hex').should.equal(xPrivKey.toString('hex'));

        c.decryptPrivateKey('password');
        c.isPrivKeyEncrypted().should.be.false;
        var xPrivKey3 = c.getDerivedXPrivKey();
        should.exist(xPrivKey3);
        xPrivKey3.toString('hex').should.equal(xPrivKey.toString('hex'));
      });
    });
  });

  describe('Utilities', function() {
    it('should get copayer hash', function() {
      var c = Credentials.fromExtendedPrivateKey('xprv9s21ZrQH143K3zLpjtB4J4yrRfDTEfbrMa9vLZaTAv5BzASwBmA16mdBmZKpMLssw1AzTnm31HAD2pk2bsnZ9dccxaLD48mRdhtw82XoiBi', {
        account: 0,
        derivationStrategy: 'BIP44'
      });
      c.copayerName = 'juan';
      var hash = c.getCopayerHash();
      hash.should.equal("juan|xpub6BtyS2Xn6ozUbhTgSAxQQzCnUwSuZWucc1amRmWi9oNsd4XTg3JmHTEpnShjF1kGs6U77ED3dEUKkCsX6vFDgFQ38G5BGh3wupZvc8DoGma|03767f64b351d3c9b85d7cbd7b682d8a2ea393b3adee6ae0668afded4000d9bdfa");
    });
  });

});
