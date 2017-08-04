import Utils from '../common/utils';
import sign from './transaction/sign';

function convertMemos(memos) {
  const stringConstructor = ''.constructor;
  const objectConstructor = {}.constructor;
  const arrayConstructor = [].constructor;

  function convertMemo(type, memo) {
    if (memo === null || memo === undefined) {
      return [];
    }
    if (memo.constructor === stringConstructor) {
      if (!memo) {
        return [];
      }
      return [{
        type,
        data: memo,
        format: 'text/plain',
      }];
    }
    if (memo.constructor === objectConstructor) {
      return [{
        type,
        data: JSON.stringify(memo),
        format: 'application/JSON',
      }];
    }
    if (memo.constructor === arrayConstructor) {
      const converted = memo.map(m => convertMemo(type, m));
      return [].concat(...converted);
    }
    return [];
  }

  const converted = Object.keys(memos).map((type) => {
    const memo = memos[type];
    return convertMemo(type, memo);
  });

  return [].concat(...converted);
}

export default class TidePayAPIClass {
  constructor(isunpayrpcURL) {
    this.isunpayrpcURL = isunpayrpcURL;
    this.dataapiURL = null;
  }

  getDataApiUrl() {
    if (this.dataapiURL) {
      return Promise.resolve(this.dataapiURL);
    }
    return fetch(`${this.isunpayrpcURL}/tidepayurl`)
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .then((value) => {
        this.dataapiURL = value.dataapi;
        console.log('data api url', this.dataapiURL);
        return Promise.resolve(this.dataapiURL);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getDataApiUrl');
      });
  }

  getGatewayAddress() {
    return fetch(`${this.isunpayrpcURL}/gatewayaddress`)
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getGatewayAddress');
      });
  }

  getCurrencies() {
    return fetch(`${this.isunpayrpcURL}/currency`)
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getCurrencies');
      });
  }

  /**
   * Get the latest withdrawal fee
   * @param {String} currency Currency to query (3-letter code)
   */
  getWithdrawalFee(currency = null) {
    const qs = { currency };
    const url = Utils.addQueryString(`${this.isunpayrpcURL}/withdrawalfee`, qs);

    return fetch(url)
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getWithdrawalFee');
      });
  }

  /**
   * Get the latest exchange rate from historical database
   * @param {String} base Base currency (3-letter code)
   * @param {String|Array} symbols Limit results to specific currencies (3-letter codes)
   */
  getExchangeRate(base = null, symbols = null) {
    return this.getDataApiUrl()
      .then((dataApiUrl) => {
        const qs = { base, symbols };
        const url = Utils.addQueryString(`${dataApiUrl}/exchange/rates`, qs);

        return fetch(url);
      })
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getExchangeRate');
      });
  }

  /**
   * Get real-time exchange rate
   * @param {String} base Base currency (3-letter code)
   * @param {String} symbol Counter currency (3-letter codes)
   */
  getRealTimeExchangeRate(base, symbol) {
    const url = `${this.isunpayrpcURL}/exchanges/rates/${base}/${symbol}`;

    return fetch(url)
      .then((res) => {
        return Utils.handleFetchResponse(res);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getRealTimeExchangeRate');
      });
  }

  getAccountBalances(address, options = {}) {
    const url = Utils.addQueryString(`${this.isunpayrpcURL}/account/${address}/balances`, options);

    return fetch(url)
      .then((resp) => {
        return Utils.handleFetchResponse(resp);
      })
      .then((json) => {
        return json.result;
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getAccountBalances');
      });
  }

  getTransactionDetail(tx_hash, options = {}) {
    return this.getDataApiUrl()
      .then((data_apiURL) => {
        const qs = {
          address: options.address,
          currency: options.currency,
          counterparty: options.counterparty,
        };
        const url = Utils.addQueryString(`${data_apiURL}/transactions/${tx_hash}`, qs);

        return fetch(url)
          .then((resp) => Utils.handleFetchResponse(resp))
          .catch((err) => Utils.handleFetchError(err, 'getTransactionsDetail'));
      });
  }

  getAccountTransactions(myAddress, options = {}) {
    return this.getDataApiUrl()
      .then((data_apiURL) => {
        const qs = {
          type: 'Payment',
          descending: true,
          currency: options.currency,
          counterparty: options.counterparty,
          rangeStart: options.rangeStart,
          limit: options.limit,
          start: options.start,
          end: options.end,
        };
        const url = Utils.addQueryString(`${data_apiURL}/accounts/${myAddress}/transactions`, qs);

        return fetch(url)
          .then((resp) => {
            return Utils.handleFetchResponse(resp);
          })
          .catch((err) => {
            return Utils.handleFetchError(err, 'getAccountTransactions');
          });
      });
  }

  sendPayment(sourceAccount, payment) {
    const pconfig = {
      method: 'POST',
      data: payment,
    };

    const poptions = Utils.makeFetchRequestOptions(pconfig);
    return fetch(`${this.isunpayrpcURL}/preparePayment`, poptions)
      .then((resp) => {
        return Utils.handleFetchResponse(resp);
      })
      .then((prepared) => {
        const signedData = sign(prepared.txJSON, sourceAccount.secret);

        const config = {
          method: 'POST',
          data: {
            signed: signedData,
            maxLedgerVersion: prepared.instructions.maxLedgerVersion,
          },
        };

        const options = Utils.makeFetchRequestOptions(config);

        return fetch(`${this.isunpayrpcURL}/signedTransaction`, options)
          .then((resp) => {
            return Utils.handleFetchResponse(resp);
          })
          .then((data) => {
            return Promise.resolve(data);
          })
          .catch((err) => {
            return Utils.handleFetchError(err, 'sendPayment');
          });
      });
  }

  sendInternalPayment(gatewayAddress, sourceAccount, destinationAddress, currency, value, clientMemo = null) {
    const amount = {
      currency,
      value: String(value),
      counterparty: gatewayAddress,
    };
    const payment = {
      source: {
        address: sourceAccount.address,
        maxAmount: amount,
      },
      destination: {
        address: destinationAddress,
        amount: amount,
      },
    };
    if (clientMemo) {
      const memos = { client: clientMemo };
      payment.memos = convertMemos(memos);
    }
    return this.sendPayment(sourceAccount, payment);
  }

  sendExternalPayment(gatewayAddress, sourceAccount, currency, value, actionMemo = null, clientMemo = null) {
    const amount = {
      currency,
      value: String(value),
      counterparty: gatewayAddress,
    };
    const payment = {
      source: {
        address: sourceAccount.address,
        maxAmount: amount,
      },
      destination: {
        address: gatewayAddress,
        amount: amount,
      },
    };
    if (actionMemo || clientMemo) {
      const memos = { action: actionMemo, client: clientMemo };
      payment.memos = convertMemos(memos);
    }
    return this.sendPayment(sourceAccount, payment);
  }

  exchangeCurrency(gatewayAddress, account, fromCurrency, fromValue, toCurrency, exchangeRate, clientMemo = null) {
    const amount = {
      currency: fromCurrency,
      value: String(fromValue),
      counterparty: gatewayAddress,
    };
    const payment = {
      source: {
        address: account.address,
        maxAmount: amount,
      },
      destination: {
        address: gatewayAddress,
        amount: amount,
      },
    };
    const memos = {
      action: {
        method: 'exchange_currency',
        params: {
          exchangeRate,
          targetCurrency: toCurrency,
        },
        notifyURI: '',
      },
    };
    if (clientMemo) {
      memos.client = clientMemo;
    }
    payment.memos = convertMemos(memos);
    return this.sendPayment(account, payment);
  }

  getAccountPockets(address) {
    const options = {
      tidepayAddress: address,
    };
    const url = Utils.addQueryString(`${this.isunpayrpcURL}/pocket`, options);

    return fetch(url)
      .then((resp) => {
        return Utils.handleFetchResponse(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getAccountPockets');
      });
  }

  getAccountPocket(address, currency) {
    const options = {
      tidepayAddress: address,
      currency,
    };
    const url = Utils.addQueryString(`${this.isunpayrpcURL}/pocket`, options);

    return fetch(url)
      .then((resp) => {
        return Utils.handleFetchResponse(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getAccountPocket');
      });
  }

  setPocket(sourceAccount, currency, frozen = false) {
    const pconfig = {
      method: 'POST',
      data: {
        address: sourceAccount.address,
        currency,
        frozen,
      },
    };

    const poptions = Utils.makeFetchRequestOptions(pconfig);
    return fetch(`${this.isunpayrpcURL}/prepareTrustline`, poptions)
      .then((resp) => {
        return Utils.handleFetchResponse(resp);
      })
      .then((prepared) => {
        const signedData = sign(prepared.txJSON, sourceAccount.secret);

        const config = {
          method: 'POST',
          data: {
            signed: signedData,
            maxLedgerVersion: prepared.instructions.maxLedgerVersion,
          },
        };

        const options = Utils.makeFetchRequestOptions(config);

        return fetch(`${this.isunpayrpcURL}/pocket`, options);
      })
      .then((resp) => {
        return Utils.handleFetchResponse(resp);
      })
      .then((data) => {
        return Promise.resolve(data);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'setPocket');
      });
  }
}
