import crypt from './crypt';
import SignedRequest from './signedrequest';
import BlobObj from './BlobObj';
import Utils from '../common/utils';
import VCUtils from './utils';

function parseContentRange(headers) {
  const contentRange = headers.get('Content-Range');
  if (!contentRange) {
    return {};
  }
  const [range, total] = contentRange.split('/');
  return { range, total };
}

function parseLinkHeader(headers) {
  const linkRE = /<.+\?(.+)>; rel="(.+)"/;
  function reduceQueryString(json, qs) {
    const pair = qs.split('=');
    const [key, value] = pair;
    return { ...json, [key]: decodeURIComponent(value || '') };      
  }
  function reduceLink(json, link) {
    const match = linkRE.exec(link);
    if (!match) {
      return json;
    }
    const [, qs, rel] = match;
    const qsJson = qs.split('&').reduce(reduceQueryString, {});
    return { ...json, [rel]: qsJson };
  }
  const link = headers.get('Link');
  if (!link) {
    return {};
  }
  return link.split(',').reduce(reduceLink, {});
}

function parseAuthorizationHeader(headers) {
  const authorization = headers.get('Authorization');
  if (!authorization) {
    return undefined;
  }
  const splitted = authorization.split(' ');
  if (splitted[0] !== 'Bearer') {
    return undefined;
  }
  return splitted.length < 2 ? null : splitted[1];
}

function fetchResponseData(resp) {
  return Utils.handleFetchResponse(resp);
}

function fetchResponseDataAndLoginToken(resp) {
  return Utils.handleFetchResponse(resp)
    .then((data) => {
      const { headers } = resp;
      const loginToken = parseAuthorizationHeader(headers);
      return { data, loginToken };
    });
}

/**
 * Get ripple name for a given address
 */

export default {
  getBlob(url, token, blobId) {
    const config = {
      method: 'GET',
      authorization: token,
    };
    const gconfig = Utils.makeFetchRequestOptions(config);
    return fetch(`${url}/v1/blob/${blobId}`, gconfig)
    .then((resp) => {
      return fetchResponseDataAndLoginToken(resp);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'getBlob');
    });
  },

  getEncryptedSecretByBlobId(url, token, blobId) {
    const config = {
      method: 'GET',
      authorization: token,
    };
    const gconfig = Utils.makeFetchRequestOptions(config);
    return fetch(`${url}/v1/secret/blob/${blobId}`, gconfig)
    .then((resp) => {
      return fetchResponseDataAndLoginToken(resp);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'getEncryptedSecretByBlobId');
    });
  },

  getEncryptedSecretBySecretId(url, token, secretId) {
    const config = {
      method: 'GET',
      authorization: token,
    };
    const gconfig = Utils.makeFetchRequestOptions(config);
    return fetch(`${url}/v1/secret/${secretId}`, gconfig)
    .then((resp) => {
      return fetchResponseDataAndLoginToken(resp);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'getEncryptedSecretBySecretId');
    });
  },

  authLogin(opts) {
    const config = Utils.makeFetchRequestOptions({ method: 'POST', data: opts.data });
    const url = `${opts.url}/v1/user/auth/login`;
    return fetch(url, config)
    .then((resp) => {
      return fetchResponseDataAndLoginToken(resp);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'authLogin');
    });
  },

  authUnblockAccount(opts) {
    const config = Utils.makeFetchRequestOptions({ method: 'POST', data: opts.data });
    const url = `${opts.url}/v1/user/auth/unblock`;
    return fetch(url, config)
    .then((resp) => {
      return fetchResponseDataAndLoginToken(resp);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'authUnblockAccount');
    });
  },

  authRecoverAccount(opts) {
    const config = Utils.makeFetchRequestOptions({ method: 'POST', data: opts.data });
    const url = `${opts.url}/v1/user/auth/recover`;
    return fetch(url, config)
    .then((resp) => {
      return fetchResponseDataAndLoginToken(resp);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'authRecoverAccount');
    });
  },

  authRecoverSecret(opts) {
    const config = Utils.makeFetchRequestOptions({ method: 'POST', data: opts.data });
    const url = `${opts.url}/v1/user/auth/recoverSecret`;
    return fetch(url, config)
    .then((resp) => {
      return fetchResponseDataAndLoginToken(resp);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'authRecoverSecret');
    });
  },

  handleRecovery(resp, customKeys) {
    return new Promise((resolve, reject) => {
      const {
        result,
        blob_id,
        blob,
        quota,
        patches,
        locked,
        encrypted_blobdecrypt_key,
        username,
        ...respRest
      } = resp;

      const params = {
        url     : customKeys.authInfo.blobvault,
        blob_id : blob_id,
        key     : customKeys.crypt,
      };

      const blobObj = new BlobObj(params);

      Object.assign(blobObj, respRest);

      if (!blobObj.decrypt(blob)) {
        reject(new Error('Error while decrypting blob'));
        return;
      }

      // Apply patches
      if (patches && patches.length) {
        let successful = true;
        patches.forEach((patch) => {
          successful = successful && blobObj.applyEncryptedPatch(patch);
        });

        if (successful) {
          blobObj.consolidate();
        }
      }

      resolve({ blob: blobObj, customKeys });
    });
  },

  /**
   * updateBlob
   * Change the blob data
   * @param {object} opts
   * @param {string} opts.username
   * @param {object} opts.keys
   * @param {object} opts.blob
   */

  updateBlob(opts) {
    const config = {
      method : 'POST',
      url    : `${opts.blob.url}/v1/user/${opts.username}/updateBlob`,
      data   : {
        data     : opts.blob.encrypt(),
        revision : opts.blob.revision,
      },
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'updateBlob');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  /**
   * updateKeys
   * Change the blob encryption keys
   * @param {object} opts
   * @param {string} opts.username
   * @param {object} opts.keys
   * @param {object} opts.blob
   * @param {string} masterkey
   */

  updateKeys(opts) {
    const old_id  = opts.blob.id;
    opts.blob.id  = opts.keys.id;
    opts.blob.key = opts.keys.crypt;

    const recoveryKey = VCUtils.createRecoveryKey(opts.blob.email);

    const config = {
      method : 'POST',
      url    : `${opts.blob.url}/v1/user/${opts.username}/updatekeys`,
      data   : {
        blob_id  : opts.blob.id,
        data     : opts.blob.encrypt(),
        revision : opts.blob.revision,
        encrypted_blobdecrypt_key : BlobObj.encryptBlobCrypt(recoveryKey, opts.keys.crypt),
      },
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, old_id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'updateKeys');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  changePaymentPin(opts) {
    const { old_secret_id, masterkey, blob, keys, loginToken } = opts;
    const secretRecoveryKey = VCUtils.createSecretRecoveryKey(blob.data.phone, blob.data.unlock_secret);
    const encryptedSecret = blob.encryptSecret(keys.unlock, masterkey);
    const encryptedUnlock = BlobObj.encryptBlobCrypt(secretRecoveryKey, keys.unlock);
    const config = {
      method: 'POST',
      url: `${blob.url}/v1/user/${opts.username}/updateSecretKeys`,
      data: {
        old_secret_id,
        secret_id: keys.secretId,
        encrypted_secret: encryptedSecret,
        encrypted_secretdecrypt_key: encryptedUnlock,
      },
      authorization: loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(blob.data.auth_secret, blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'updateSecretKeys');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  /**
   * Activate an account
   */

  authActivateAccount(opts) {
    const { keys, email, masterkey, address, username, url, authToken, blobData, unlockSecret } = opts;

    const params = {
      url,
      blob_id: keys.id,
      key: keys.crypt,
    };

    const blob = new BlobObj(params);

    blob.revision = 0;

    blob.data = {
      ...blobData,
      account_id: address,
      activated: (new Date()).toJSON(),
      unlock_secret: unlockSecret,
    };

    const encrypted_secret = blob.encryptSecret(keys.unlock, masterkey);

    const recoveryKey = VCUtils.createRecoveryKey(email);

    const config = {
      method: 'POST',
      url: `${url}/v1/user/${username}/auth/activate`,
      data: {
        address,
        email,
        authToken,
        data: blob.encrypt(),
        encrypted_secret,
        encrypted_blobdecrypt_key: BlobObj.encryptBlobCrypt(recoveryKey, keys.crypt),
      },
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signAsymmetric(masterkey, address, keys.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .then((resp) => {
        const { data, loginToken } = resp;
        return {
          data: { ...data, newBlobData: blob.data },
          loginToken,
        };
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'authActivateAccount');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  authVerifyAccountEmailToken(opts) {
    const { email, emailToken, username, authToken } = opts;
    const config = Utils.makeFetchRequestOptions({
      method: 'POST',
      data: {
        email,
        emailToken,
        authToken,
      },
    });
    const url = `${opts.url}/v1/user/${username}/auth/verify`;
    return fetch(url, config)
    .then((resp) => {
      return fetchResponseData(resp);
    })
    .then((data) => {
      return Promise.resolve(data);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'authVerifyAccountEmailToken');
    });
  },

  authRequestUpdateEmail(opts) {
    const config = {
      method: 'POST',
      url: `${opts.url}/v1/user/${opts.username}/email/request`,
      data: opts.data,
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'authRequestUpdateEmail');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  authVerifyUpdateEmail(opts) {
    const config = {
      method: 'POST',
      url: `${opts.url}/v1/user/${opts.username}/email/verify`,
      data: opts.data,
    };

    const options = Utils.makeFetchRequestOptions(config);

    return fetch(config.url, options)
    .then((resp) => {
      return fetchResponseData(resp);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'authVerifyUpdateEmail');
    });
  },

  authUpdateEmail(opts) {
    const config = {
      method: 'POST',
      url: `${opts.url}/v1/user/${opts.username}/email/update`,
      data: opts.data,
    };

    const options = Utils.makeFetchRequestOptions(config);

    return fetch(config.url, options)
    .then((resp) => {
      return fetchResponseData(resp);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'authVerifyUpdateEmail');
    });
  },

  authRequestUpdatePhone(opts) {
    const config = {
      method : 'POST',
      url    : `${opts.url}/v1/user/${opts.username}/phone/request`,
      data   : opts.data,
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'authRequestUpdatePhone');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  authVerifyUpdatePhone(opts) {
    const config = {
      method : 'POST',
      url    : `${opts.url}/v1/user/${opts.username}/phone/verify`,
      data   : opts.data,
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'authVerifyUpdatePhone');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  authUpdatePhone(opts) {
    const config = {
      method : 'POST',
      url    : `${opts.url}/v1/user/${opts.username}/phone/update`,
      data   : opts.data,
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'authUpdatePhone');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  /**
   * Create a blob object
   *
   * @param {object} opts
   * @param {string} opts.url
   * @param {string} opts.id
   * @param {string} opts.crypt
   * @param {string} opts.username
   * @param {object} opts.domain
   */
  authCreate(opts) {
    const params = {
      url     : opts.url,
      blob_id : opts.id,
      key     : opts.crypt,
    };
    const blob = new BlobObj(params);

    blob.revision = 0;

    blob.data = {
      auth_secret : crypt.createSecret(8),
      created     : (new Date()).toJSON(),
      phone       : null,
    };

    const recoveryKey = VCUtils.createRecoveryKey(opts.email);

    // post to the blob vault to create
    const config = Utils.makeFetchRequestOptions({
      method : 'POST',
      data   : {
        blob_id     : opts.id,
        username    : opts.username,
        auth_secret : blob.data.auth_secret,
        data        : blob.encrypt(),
        email       : opts.email,
        hostlink    : opts.activateLink,
        domain      : opts.domain,
        encrypted_blobdecrypt_key : BlobObj.encryptBlobCrypt(recoveryKey, opts.crypt),
      },
    });
    return fetch(`${opts.url}/v1/user/auth`, config)
    .then((resp) => {
      return fetchResponseData(resp);
    })
    .then((data) => {
      blob.identity_id = data.identity_id;
      return Promise.resolve(blob);
    })
    .catch((err) => {
      return Utils.handleFetchError(err, 'authCreate');
    });
  },

  /**
   * deleteBlob
   * @param {object} options
   * @param {string} options.url
   * @param {string} options.username
   * @param {string} options.blob_id
   * @param {string} options.auth_secret
   */

  deleteBlob(options) {
    const config = {
      method: 'DELETE',
      url: `${options.url}/v1/user/${options.username}`,
      authorization: options.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(options.auth_secret, options.blob_id);

      return fetch(signed.url, { method: 'DELETE' })
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'deleteBlob');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  /**
   * Block an account
   * @param {object} opts
   * @param {string} opts.url
   * @param {string} opts.username
   * @param {string} opts.blob_id
   * @param {string} opts.auth_secret
   */

  blockAccount(opts) {
    const config = {
      method : 'POST',
      url    : `${opts.url}/v1/user/${opts.username}/block`,
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.auth_secret, opts.blob_id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'blockAccount');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  /**
   * Add bank account
   * @param {object} opts
   * @param {object} opts.blob
   * @param {object} opts.bankAccountInfo
   */

  addBankAccount(opts) {
    const config = {
      method: 'POST',
      url: `${opts.blob.url}/v1/blob/${opts.blob.id}/bankaccount`,
      data: {
        data     : opts.blob.encrypt(),
        revision : opts.blob.revision,
        bank_account_info: opts.bankAccountInfo,
      },
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'addBankAccount');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  uploadBankAccountVerification(opts) {
    const formData = new FormData();
    formData.append('bank_account_info', JSON.stringify(opts.bankAccountInfo));
    formData.append('transaction_time_range_start', opts.transactionDateRange.start);
    formData.append('transaction_time_range_end', opts.transactionDateRange.end);
    formData.append('amount', opts.value);
    formData.append('currency', opts.currency);
    formData.append('receipt_photo', opts.receiptPhoto);
    const config = {
      method: 'POST',
      url: `${opts.blob.url}/v1/blob/${opts.blob.id}/bankaccount/verify`,
      data: formData,
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'uploadBankAccountVerification');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  /**
   * Delete bank account
   * @param {object} opts
   * @param {object} opts.blob
   * @param {object} opts.bankAccountInfo
   */

  deleteBankAccount(opts) {
    const config = {
      method: 'DELETE',
      url: `${opts.blob.url}/v1/blob/${opts.blob.id}/bankaccount`,
      data: {
        data     : opts.blob.encrypt(),
        revision : opts.blob.revision,
        bank_account_info: opts.bankAccountInfo,
      },
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'deleteBankAccount');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },


  /**
   * get2FA - HMAC signed request
   */

  get2FA(opts) {
    const { blob, loginToken } = opts;
    const config = {
      method : 'GET',
      url    : `${blob.url}/v1/blob/${blob.id}/2fa`,
      authorization: loginToken,
    };
    if (blob.device_id) {
      config.url += `?device_id=${blob.device_id}`;
    }

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(blob.data.auth_secret, blob.id);
      const options = Utils.makeFetchRequestOptions(config);
      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'get2FA');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  /**
   * set2FA
   * modify 2 factor auth settings
   * @params {object}  opts
   * @params {boolean} opts.enabled
   * @params {string}  opts.phoneNumber
   * @params {string}  opts.countryCode
   */

  set2FA(opts) {
    const config = {
      method : 'POST',
      url    : `${opts.blob.url}/v1/blob/${opts.blob.id}/2fa`,
      data   : {
        enabled     : opts.enabled,
        phoneNumber : opts.phoneNumber,
        countryCode : opts.countryCode,
      },
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'set2FA');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  enable2FAGoogle(opts) {
    const config = {
      method: 'POST',
      url: `${opts.blob.url}/v1/blob/${opts.blob.id}/2fa/gauth`,
      data: {
        key: opts.gKey,
        gToken: opts.gToken,
      },
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'enable2FAGoogle');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  enable2FASmsRequest(opts) {
    const config = {
      method: 'POST',
      url: `${opts.blob.url}/v1/blob/${opts.blob.id}/2fa/sms/request`,
      data: {
        phoneNumber: opts.phoneNumber,
        countryCode: opts.countryCode,
      },
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'enable2FASmsRequest');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  enable2FASms(opts) {
    const config = {
      method: 'POST',
      url: `${opts.blob.url}/v1/blob/${opts.blob.id}/2fa/sms`,
      data: {
        phoneNumber: opts.phoneNumber,
        countryCode: opts.countryCode,
        smsToken: opts.smsToken,
        authToken: opts.authToken,
      },
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'enable2FASms');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  disable2FAGoogle(opts) {
    const config = {
      method: 'POST',
      url: `${opts.blob.url}/v1/blob/${opts.blob.id}/2fa/disable`,
      data: {
        gToken: opts.gToken,
      },
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'disable2FAGoogle');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  disable2FASmsRequest(opts) {
    const config = {
      method: 'POST',
      url: `${opts.blob.url}/v1/blob/${opts.blob.id}/2fa/disable/request`,
      data: {
        phoneNumber: opts.phoneNumber,
        countryCode: opts.countryCode,
      },
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'disble2FASmsRequest');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  disable2FASms(opts) {
    const config = {
      method: 'POST',
      url: `${opts.blob.url}/v1/blob/${opts.blob.id}/2fa/disable`,
      data: {
        phoneNumber: opts.phoneNumber,
        countryCode: opts.countryCode,
        smsToken: opts.smsToken,
        authToken: opts.authToken,
      },
      authorization: opts.loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(opts.blob.data.auth_secret, opts.blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'disable2FASms');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  uploadPhotos(opts) {
    const config = {
      method: 'POST',
      data: opts.formData,
      authorization: opts.loginToken,
    };
    const options = Utils.makeFetchRequestOptions(config);
    const url = `${opts.blob.url}/v1/blob/${opts.blob.id}/uploadId`;
    return fetch(url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'uploadPhotos');
      });
  },

  logoutAccount(opts) {
    const { blob, loginToken } = opts;
    const config = {
      method: 'POST',
      url: `${blob.url}/v1/user/auth/logout`,
      authorization: loginToken,
    };
    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(blob.data.auth_secret, blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'logoutAccount');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  getUserJournalsPagination(opts) {
    const { blob, username, offset, limit, filter, loginToken } = opts;
    const qs = { offset, limit, messageId: filter };
    const config = {
      method: 'GET',
      url: Utils.addQueryString(`${blob.url}/v1/user/${username}/journals`, qs),
      authorization: loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(blob.data.auth_secret, blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseData(resp)
          .then((data) => {
            const { headers } = resp;
            const { total } = parseContentRange(headers);
            const link = parseLinkHeader(headers);
            const refreshedLoginToken = parseAuthorizationHeader(headers);
            return {
              data: { ...data, total, link },
              loginToken: refreshedLoginToken,
            };
          });
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getUserJournals');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  getUserJournals(opts) {
    const { blob, username, marker, limit, filter, loginToken } = opts;
    const qs = { marker, limit, messageId: filter };
    const config = {
      method: 'GET',
      url: Utils.addQueryString(`${blob.url}/v1/user/${username}/journals`, qs),
      authorization: loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(blob.data.auth_secret, blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseData(resp)
          .then((data) => {
            const { headers } = resp;
            const link = parseLinkHeader(headers);
            const refreshedLoginToken = parseAuthorizationHeader(headers);
            return {
              data: { ...data, link },
              loginToken: refreshedLoginToken,
            };
          });
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getUserJournals');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  getUserJournalsUnreadCount(opts) {
    const { blob, username, filter, loginToken } = opts;
    const qs = { messageId: filter };
    const config = {
      method: 'GET',
      url: Utils.addQueryString(`${blob.url}/v1/user/${username}/journals/unreadCount`, qs),
      authorization: loginToken,
    };

    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(blob.data.auth_secret, blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'getUserJournals');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  setUserJournalStatus(opts) {
    const { blob, username, journalId, read, loginToken } = opts;
    const qs = { journalId };
    const config = {
      method: 'PUT',
      url: Utils.addQueryString(`${blob.url}/v1/user/${username}/journals/status`, qs),
      authorization: loginToken,
      data: {
        read,
      },
    };
    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(blob.data.auth_secret, blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'setUserJournalStatus');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },

  setAllUserJournalStatus(opts) {
    const { blob, username, filter, read, loginToken } = opts;
    const qs = { messageId: filter };
    const config = {
      method: 'PUT',
      url: Utils.addQueryString(`${blob.url}/v1/user/${username}/journals/status`, qs),
      authorization: loginToken,
      data: {
        read,
      },
    };
    try {
      const signedRequest = new SignedRequest(config);
      const signed = signedRequest.signHmac(blob.data.auth_secret, blob.id);
      const options = Utils.makeFetchRequestOptions(config);

      return fetch(signed.url, options)
      .then((resp) => {
        return fetchResponseDataAndLoginToken(resp);
      })
      .catch((err) => {
        return Utils.handleFetchError(err, 'setAllUserJournalStatus');
      });
    } catch (err) {
      return Promise.reject(err);
    }
  },
};
