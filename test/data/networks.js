'use strict;'

var Bip44 = require('bip44-constants');
var networkLib = require('@owstack/network-lib');
var Networks = networkLib.Networks;

Networks.add([{
	name: 'Bitcoin',
	symbol: 'BTC',
	coin: Bip44['BTC'] ^ 0x80000000,
	protocol: 'bitcoin',
	prefix: {
	  pubkeyhash: 0x00,
	  privatekey: 0x80,
	  scripthash: 0x05,
	},
	version: {
	  xpubkey: 0x0488b21e,
	  xprivkey: 0x0488ade4
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
	],
	indexBy: Networks.indexAll
}, {
	name: 'Bitcoin Cash',
	symbol: 'BCH',
	coin: Bip44['BCH'] ^ 0x80000000,
	protocol: 'bitcoincash',
	prefix: {
	  pubkeyhash: 0x00,
	  privatekey: 0x80,
	  scripthash: 0x05,
	},
	version: {
	  xpubkey: 0x03f72812, // 'qpub..' (no BCH version strings registered); see SLIP132
	  xprivkey: 0x03f723d8 // 'qprv..' (no BCH version strings registered); see SLIP132
	},
  networkMagic: 0xe3e1f3e8,
	port: 8333,
	dnsSeeds: [
    'seed.bitcoinabc.org',
    'seed-abc.bitcoinforks.org',
    'btccash-seeder.bitcoinunlimited.info',
    'seed.bitprim.org ',
    'seed.deadalnix.me'
	],
	indexBy: Networks.indexAll
}, {
	name: 'Litecoin',
	symbol: 'LTC',
	coin: Bip44['LTC'] ^ 0x80000000,
	protocol: 'litecoin',
	prefix: {
		pubkeyhash: 0x30,
	  privatekey: 0xb0,
	  scripthash: 0x05,
	  scripthash2: 0x32,
	},
	version: {
	  xpubkey: 0x019da462,
	  xprivkey: 0x019d9cfe,
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
	],
	indexBy: Networks.indexAll
}, {
	name: 'BCH Testnet',
	symbol: 'BCHTEST',
	coin: 0x00000001 ^ 0x80000000,
	protocol: 'bchtest',
	prefix: {
		pubkeyhash: 0x6f,
	  privatekey: 0xef,
	  scripthash: 0xc4
	},
	version: {
	  xpubkey: 0x0435dbaa, // 'tqpb..' (no BCH testnet version strings registered); see SLIP132
	  xprivkey: 0x0435dc2e // 'tqpv..' (no BCH testnet version strings registered); see SLIP132
	},
  networkMagic: 0x0b110907,
	port: 18333,
	dnsSeeds: [
		'testnet-seed.bitcoin.petertodd.org',
    'testnet-seed.bluematt.me',
    'testnet-seed.alexykot.me',
    'testnet-seed.bitcoin.schildbach.de'
	],
	indexBy: Networks.indexAll
}]);
