'use strict';

var Constants = {};

Constants.SCRIPT_TYPES = {
  P2SH: 'P2SH',
  P2PKH: 'P2PKH',
};
Constants.DERIVATION_STRATEGIES = {
  BIP44: 'BIP44',
  BIP45: 'BIP45',
  BIP48: 'BIP48',
};

Constants.PATHS = {
  REQUEST_KEY: "m/1'/0",
  REQUEST_KEY_AUTH: "m/2", // relative to BASE
};

Constants.BIP45_SHARED_INDEX = 0x80000000 - 1;

module.exports = Constants;
