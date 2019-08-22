const _ = require('lodash');
const axios = require('axios');
const CryptoJS = require("crypto-js");
const pkg = require('./package.json');

const API_BASE_URL = 'https://api2.nicehash.com';
const API_TIME_URL = ''
const axiosConfig = {
    baseURL: API_BASE_URL,
    timeout: 1000 * 10,
}

const ALGORITHMS = {
    0: 'Scrypt',
    1: 'SHA256',
    2: 'ScryptNf',
    3: 'X11',
    4: 'X13',
    5: 'Keccak',
    6: 'X15',
    7: 'Nist5',
    8: 'NeoScrypt',
    9: 'Lyra2RE',
    10: 'WhirlpoolX',
    11: 'Qubit',
    12: 'Quark',
    13: 'Axiom',
    14: 'Lyra2REv2',
    15: 'ScryptJaneNf16',
    16: 'Blake256r8',
    17: 'Blake256r14',
    18: 'Blake256r8vnl',
    19: 'Hodl',
    20: 'DaggerHashimoto',
    21: 'Decred',
    22: 'CryptoNight',
    23: 'Lbry',
    24: 'Equihash',
    25: 'Pascal',
    26: 'X11Gost',
    27: 'Sia',
    28: 'Blake2s',
    29: 'Skunk',
    30: 'CryptoNightV7',
    31: 'CryptoNightHeavy',
    32: 'Lyra2Z',
    33: 'X16R',
    34: 'CryptoNightV8',
    35: 'SHA256AsicBoost',
    36: 'Zhash',
    37: 'Beam',
    38: 'GrinCuckaroo29',
    39: 'GrinCuckatoo31',
    40: 'Lyra2REv3',
    41: 'MTP',
    42: 'CryptoNightR',
    43: 'CuckooCycle',
};

ALGORITHM_UNITS = {
    0: 'MH/s',
    1: 'TH/s',
    2: 'MH/s',
    3: 'MH/s',
    4: 'MH/s',
    5: 'MH/s',
    6: 'MH/s',
    7: 'MH/s',
    8: 'MH/s',
    9: 'MH/s',
    10: 'MH/s',
    11: 'MH/s',
    12: 'MH/s',
    13: 'kH/s',
    14: 'MH/s',
    15: 'kH/s',
    16: 'GH/s',
    17: 'GH/s',
    18: 'GH/s',
    19: 'kH/s',
    20: 'MH/s',
    21: 'GH/s',
    22: 'kH/s',
    23: 'GH/s',
    24: 'Sol/s',
    25: 'GH/s',
    26: 'MH/s',
    27: 'GH/s',
    28: 'GH/s',
    29: 'MH/s',
    30: 'kH/s',
    31: 'kH/s',
    32: 'MH/s',
    33: 'MH/s',
    34: 'kH/s',
    35: 'TH/s',
    36: 'Sol/s',
    37: 'Sol/s',
    38: 'G/s',
    39: 'G/s',
    40: 'MH/s',
    41: 'MH/s',
    42: 'kH/s',
    43: 'G/s',
}

const ORDER_TYPES = {
    0: 'standard',
    1: 'fixed'
};

class NiceHashClient {
    /**
     * Creates a new client
     * @param options Object
     * @param options.apiKey String - API Key
     * @param options.apiSecret String - API Secret
     * @param options.orgsnizationId String - Organization Id
     */
    constructor(options) {
        this.apiKey = _.get(options, 'apiKey');
        this.apiSecret = _.get(options, 'apiSecret');
        this.organizationId = _.get(options, 'organizationId', '');
        this.axios = axios.create(axiosConfig);
    }

    hasAuthTokens() {
        return !!this.apiKey && !!this.apiSecret;;
    }

    getAuthParams() {
        return { key: this.apiKey, seccret: this.apiSecret };
    }

    getRandomString() {
        return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    }

    getServerTimestamp() {
        return Date.now().toString()

        axios.get(API_TIME_URL).then((response) => {
            return response.data.serverTime.toString()
        }).catch((err) => {
            console.log('Error getting server time', err)
            console.log('Using local system timestamp')
            return Date.now()
        })
    }

    /**
     * Generates the byte array composed of ordered fields using zero byte (0x00) as a seperator.
     * 
     *  - There is no seperator before the first field and after the last field.
     *  - Some fields are always empty in which case the separators immediately follow one another. 
     *  - If converting HTTP header values, and url parts from string to byte representation you should use ISO-8859-1 encoding. 
     *  - For request body you should use the raw bytes as they are sent to the server. 
     *  - For JSON messages the character encoding should always be UTF-8.
     * @param {inputList} array - Array of input strings
     */
    generateInputBuffer(inputList) {
        // Generate list of Buffer
        let bufferList = [];
        for (let i = 0; i < inputList.length; i++) {
            if (inputList[i] != '') {
                bufferList.push(Buffer.from(inputList[i], 'latin1'));    // assuming ISO-8859-1 and LATIN_1 are the same Charset
            }

            // Add zero byte (0x00) seperator between bytes of input's ordered fields
            if(i != inputList.length-1) {
                bufferList.push(Buffer.from([0x00]));
            }
        }

        // Join all Buffer in list
        return Buffer.concat(bufferList);
    }

    /**
     * Generates the HMAC-SHA256 signature used for signing the API call and used in the X-Auth header
     * @param {inputList} array - List of string inputs that will be hashed
     */
    generateHmacSha256Signature(inputList) {
        return 'signature'
    }

    getHeaders(httpMethod, requestPath, params) {
        return 'headers'
    }

    getHeadersUnsigned() {
        return {
            'user-agent': `NiceHashJs/${pkg.version} (https://github.com/dannychua/nicehashjs2)`,
        }
    }

    getRequestPromise(httpMethod, requestPath, params) {
        const payload = _.merge({headers: this.getHeaders(httpMethod, requestPath, params)}, {params: params });
        return this.axios.get(requestPath, payload)
    }

    getUnsignedRequestPromise(httpMethod, requestPath, params) {
        const payload = _.merge({headers: this.getHeadersUnsigned()}, {params: params });
        return this.axios.get(requestPath, payload)
    }

    getWallets() {
        return this.getRequestPromise('GET', '/main/api/v2/accounting/accounts', {})
    }

    getPayouts() {
        return this.getRequestPromise('GET', '/main/api/v2/mining/rigs/payouts', {})
    }

    getHashpowerEarnings() {
        const currency = 'BTC'
        const params = {
            op: 'LT',
            timestamp: Date.now(),
        }
        return this.getRequestPromise('GET', '/main/api/v2/accounting/hashpowerEarnings/'+currency, params)
    }
    
    getMiningRigs() {
        return this.getRequestPromise('GET', '/main/api/v2/mining/rigs', {})
    }

    getMiningRigsStats(afterTimestamp) {
        const params = {}
        if(afterTimestamp) {
            params['afterTimestamp'] = afterTimestamp
        }

        return this.getRequestPromise('GET', '/main/api/v2/mining/rigs/stats', params)
    }

    /**
     * Get the latest forex exchange rates
     * 
     *  - This is a public API endpoint
     */
    getExchangeRates() {
        return this.getUnsignedRequestPromise('GET', '/main/api/v2/exchangeRate/list', {});
    }
}

module.exports = NiceHashClient;