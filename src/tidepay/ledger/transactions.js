
/* eslint-disable max-params */
'use strict'; // eslint-disable-line strict

var _ = require('lodash');
var binary = require('../tidepay-binary-codec');

var _require = require('../tidepay-hashes'),
    computeTransactionHash = _require.computeTransactionHash;

var utils = require('./utils');
var parseTransaction = require('./parse/transaction');
var getTransaction = require('./transaction');
var validate = utils.common.validate;


function parseBinaryTransaction(transaction) {
  var tx = binary.decode(transaction.tx_blob);
  tx.hash = computeTransactionHash(tx);
  tx.ledger_index = transaction.ledger_index;
  return {
    tx: tx,
    meta: binary.decode(transaction.meta),
    validated: transaction.validated
  };
}

function parseAccountTxTransaction(tx) {
  var _tx = tx.tx_blob ? parseBinaryTransaction(tx) : tx;
  // rippled uses a different response format for 'account_tx' than 'tx'
  return parseTransaction(_.assign({}, _tx.tx, { meta: _tx.meta, validated: _tx.validated }));
}

function counterpartyFilter(filters, tx) {
  if (tx.address === filters.counterparty || tx.specification && (tx.specification.destination && tx.specification.destination.address === filters.counterparty || tx.specification.counterparty === filters.counterparty)) {
    return true;
  }
  return false;
}

function transactionFilter(address, filters, tx) {
  if (filters.excludeFailures && tx.outcome.result !== 'tesSUCCESS') {
    return false;
  }
  if (filters.types && !_.includes(filters.types, tx.type)) {
    return false;
  }
  if (filters.initiated === true && tx.address !== address) {
    return false;
  }
  if (filters.initiated === false && tx.address === address) {
    return false;
  }
  if (filters.counterparty && !counterpartyFilter(filters, tx)) {
    return false;
  }
  return true;
}

function orderFilter(options, tx) {
  return !options.startTx || (options.earliestFirst ? utils.compareTransactions(tx, options.startTx) > 0 : utils.compareTransactions(tx, options.startTx) < 0);
}

function formatPartialResponse(address, options, data) {
  return {
    marker: data.marker,
    results: data.transactions.filter(function (tx) {
      return tx.validated;
    }).map(parseAccountTxTransaction).filter(_.partial(transactionFilter, address, options)).filter(_.partial(orderFilter, options))
  };
}

function getAccountTx(api, address, options, marker, limit) {
  var request = {
    account: address,
    // -1 is equivalent to earliest available validated ledger
    ledger_index_min: options.minLedgerVersion || -1,
    // -1 is equivalent to most recent available validated ledger
    ledger_index_max: options.maxLedgerVersion || -1,
    forward: options.earliestFirst,
    binary: options.binary,
    limit: utils.clamp(limit, 10, 400),
    marker: marker
  };

  return api.doAccountTx(request).then(function (response) {
    return formatPartialResponse(address, options, response);
  });
}

function checkForLedgerGaps(api, options, transactions) {
  var minLedgerVersion = options.minLedgerVersion,
      maxLedgerVersion = options.maxLedgerVersion;

  // if we reached the limit on number of transactions, then we can shrink
  // the required ledger range to only guarantee that there are no gaps in
  // the range of ledgers spanned by those transactions

  if (options.limit && transactions.length === options.limit) {
    if (options.earliestFirst) {
      maxLedgerVersion = _.last(transactions).outcome.ledgerVersion;
    } else {
      minLedgerVersion = _.last(transactions).outcome.ledgerVersion;
    }
  }

  return utils.hasCompleteLedgerRange(api, minLedgerVersion, maxLedgerVersion).then(function (hasCompleteLedgerRange) {
    if (!hasCompleteLedgerRange) {
      throw new utils.common.errors.MissingLedgerHistoryError();
    }
  });
}

function formatResponse(api, options, transactions) {
  var compare = options.earliestFirst ? utils.compareTransactions : _.rearg(utils.compareTransactions, 1, 0);
  var sortedTransactions = transactions.sort(compare);
  if (options.notCheckGaps) {
    return Promise.resolve(sortedTransactions);
  }
  return checkForLedgerGaps(api, options, sortedTransactions).then(function () {
    return sortedTransactions;
  });
}

function getTransactionsInternal(api, address, options) {
  var getter = _.partial(getAccountTx, api, address, options);
  var format = _.partial(formatResponse, api, options);
  return utils.getRecursive(getter, options.limit).then(format);
}

function getTransactions(address) {
  var _this = this;

  var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

  validate.getTransactions({ address: address, options: options });

  var defaults = { maxLedgerVersion: -1 };
  if (options.start) {
    return getTransaction.call(this, options.start).then(function (tx) {
      var ledgerVersion = tx.outcome.ledgerVersion;
      var bound = options.earliestFirst ? { minLedgerVersion: ledgerVersion } : { maxLedgerVersion: ledgerVersion };
      var newOptions = _.assign({}, defaults, options, { startTx: tx }, bound);
      return getTransactionsInternal(_this, address, newOptions);
    });
  }
  if (options.startTx) {
    const tx = options.startTx;
    var ledgerVersion = tx.outcome.ledgerVersion;
    var bound = options.earliestFirst ? { minLedgerVersion: ledgerVersion } : { maxLedgerVersion: ledgerVersion };
    var newOptions = _.assign({}, defaults, options, { startTx: tx }, bound);
    return getTransactionsInternal(_this, address, newOptions);
  }
  var newOptions = _.assign({}, defaults, options);
  return getTransactionsInternal(this, address, newOptions);
}

module.exports = getTransactions;