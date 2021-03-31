"use strict";

var crypto = require('crypto');

exports._createCipher = function(algorithm) {
  return function(password) {
    return function() {
      return crypto.createCipher(algorithm, password);
    };
  };
};

exports._createCipherIV = function(algorithm) {
  return function(password) {
    return function(iv) {
      return function () {
        return crypto.createCipheriv(algorithm, password, iv);
      };
    };
  };
};

exports.update = function(cipher) {
  return function(buffer) {
    return function() {
      return cipher.update(buffer);
    };
  };
};

exports.final = function(cipher) {
  return function() {
    return cipher.final();
  };
};
