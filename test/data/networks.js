'use strict;'

var Bip44 = require('bip44-constants');
var Networks = require('@owstack/network-lib');

Networks.add([{
  currency: 'BTC',
  description: 'Bitcoin',
	name: 'BTC',
	coinIndex: Bip44['BTC'] ^ 0x80000000,
	protocol: 'bitcoin',
  alias: 'livenet',
	prefix: {
	  pubkeyhash: 0x00,
	  privatekey: 0x80,
	  scripthash: 0x05,
	},
  version: { // see SLIP132
    xpubkey: {
      bytes: 0x0488b21e,
      text: 'xpub'
    },
    xprivkey: {
      bytes: 0x0488ade4,
      text: 'xprv'
    }
  },
  networkMagic: 0xf9beb4d9,
	port: 8333,
	dnsSeeds: [
    'seed.bitcoin.sipa.be',
    'dnsseed.bluematt.me',
    'dnsseed.bitcoin.dashjr.org',
    'seed.bitcoinstats.com',
    'seed.bitnodes.io',
    'bitseed.xf2.org'
	]
}, {
  currency: 'BCH',
	description: 'Bitcoin Cash',
	name: 'BCH',
	coinIndex: Bip44['BCH'] ^ 0x80000000,
	protocol: 'bitcoincash',
  alias: 'livenet',
	prefix: {
	  pubkeyhash: 0x00,
	  privatekey: 0x80,
	  scripthash: 0x05,
	},
  version: { // see SLIP132 (no BCH version strings registered)
    xpubkey: {
      bytes: 0x03f72812,
      text: 'qpub'
    },
    xprivkey: {
      bytes: 0x03f723d8,
      text: 'qprv'
    }
  },
  networkMagic: 0xe3e1f3e8,
	port: 8333,
	dnsSeeds: [
    'seed.bitcoinabc.org',
    'seed-abc.bitcoinforks.org',
    'btccash-seeder.bitcoinunlimited.info',
    'seed.bitprim.org ',
    'seed.deadalnix.me'
	]
}, {
  currency: 'LTC',
	description: 'Litecoin',
	name: 'LTC',
	coinIndex: Bip44['LTC'] ^ 0x80000000,
	protocol: 'litecoin',
  alias: 'livenet',
	prefix: {
		pubkeyhash: 0x30,
	  privatekey: 0xb0,
	  scripthash: 0x05,
	  scripthash2: 0x32,
	},
  version: { // see SLIP132
    xpubkey: {
      bytes: 0x019da462,
      text: 'Ltub'
    },
    xprivkey: {
      bytes: 0x019d9cfe,
      text: 'Ltpv'
    }
  },
  networkMagic: 0xfbc0b6db,
	port: 9333,
	dnsSeeds: [
    'dnsseed.litecointools.com',
    'dnsseed.litecoinpool.org',
    'dnsseed.ltc.xurious.com',
    'dnsseed.koin-project.com',
    'seed-a.litecoin.loshan.co.uk',
    'dnsseed.thrasher.io'
	]
}, {
  currency: 'BCH',
	description: 'BCH Testnet',
	name: 'BCHTEST',
	coinIndex: 0x00000001 ^ 0x80000000,
	protocol: 'bchtest',
  alias: 'testnet',
	prefix: {
		pubkeyhash: 0x6f,
	  privatekey: 0xef,
	  scripthash: 0xc4
	},
  version: { // see SLIP132 (no BCH version strings registered)
    xpubkey: {
      bytes: 0x0435dbaa,
      text: 'tqpb'
    },
    xprivkey: {
      bytes: 0x0435dc2e,
      text: 'tqpv'
    }
  },
  networkMagic: 0x0b110907,
	port: 18333,
	dnsSeeds: [
		'testnet-seed.bitcoin.petertodd.org',
    'testnet-seed.bluematt.me',
    'testnet-seed.alexykot.me',
    'testnet-seed.bitcoin.schildbach.de'
	]
}]);
