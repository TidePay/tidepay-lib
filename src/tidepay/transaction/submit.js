'use strict'; // eslint-disable-line strict

var _ = require('lodash');
var utils = require('./utils');
var validate = utils.common.validate;


function isImmediateRejection(engineResult) {
  // note: "tel" errors mean the local server refused to process the
  // transaction *at that time*, but it could potentially buffer the
  // transaction and then process it at a later time, for example
  // if the required fee changes (this does not occur at the time of
  // this writing, but it could change in the future)
  // all other error classes can potentially result in transaction validation
  return _.startsWith(engineResult, 'tem');
}

function formatSubmitResponse(response) {
  var data = {
    resultCode: response.engine_result,
    resultMessage: response.engine_result_message
  };
  if (isImmediateRejection(response.engine_result)) {
    throw new utils.common.errors.RippledError('Submit failed', data);
  }
  return data;
}

function submit(signedTransaction) {
  validate.submit({ signedTransaction: signedTransaction });

  var request = {
    tx_blob: signedTransaction
  };
  return this.doSubmit(request).then(formatSubmitResponse);
}

module.exports = submit;