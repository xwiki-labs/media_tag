/* global window, fetch, XMLHttpRequest, Blob, Event */
const Errors = 			require('../errors');
const RunningEngine = 	require('../engines/running-engine');
    const PARANOIA = true;
    const plainChunkLength = 128 * 1024;
    const cypherChunkLength = 131088;
/**
 * Class for crypto.
 *
 * @class      Crypto (name)
 */
class Cryptopad {

  
  	/**
	 * Create a nonce
	 */
    static createNonce () {
        return new Uint8Array(new Array(24).fill(0));
    }

   /**
	 * Increment a nonce
     * @param      {Uint8Array}  u8      The nonce
	 */
    static increment (N) {
        var l = N.length;
        while (l-- > 1) {
            if (PARANOIA) {
                if (typeof(N[l]) !== 'number') {
                    throw new Error('E_UNSAFE_TYPE');
                }
                if (N[l] > 255) {
                    throw new Error('E_OUT_OF_BOUNDS');
                }
            }
        /*  jshint probably suspects this is unsafe because we lack types
            but as long as this is only used on nonces, it should be safe  */
            if (N[l] !== 255) { return void N[l]++; } // jshint ignore:line
            N[l] = 0;

            // you don't need to worry about this running out.
            // you'd need a REAAAALLY big file
            if (l === 0) {
                throw new Error('E_NONCE_TOO_LARGE');
            }
        }
    }

    static joinChunks (chunks) {
        return new Uint8Array(chunks.reduce(function (A, B) {
            return Cryptopad.slice(A).concat(Cryptopad.slice(B));
        }, []));
    }

    static padChunk (A) {
        var padding;
        if (A.length === plainChunkLength) { return A; }
        if (A.length < plainChunkLength) {
            padding = new Array(plainChunkLength - A.length).fill(32);
            return A.concat(padding);
        }
        if (A.length > plainChunkLength) {
            // how many times larger is it?
            var chunks = Math.ceil(A.length / plainChunkLength);
            padding = new Array((plainChunkLength * chunks) - A.length).fill(32);
            return A.concat(padding);
        }
    }

	/**
	 * Convert a Uint8Array into Array.
	 *
	 * @param      {Uint8Array}  u8      The u 8
	 * @return     {Array}  Array = require(Uint8Array.
	 */
	static slice(u8) {
		return Array.prototype.slice.call(u8);
	}

	/**
	 * Gets the random key string.
	 *
	 * @return     {String}  The random key string.
	 */
	static getRandomKeyStr() {
		const Nacl = Cryptopad.Nacl;
		const rdm = Nacl.randomBytes(18);
		return Nacl.util.encodeBase64(rdm);
	}

	/**
	 * Gets the key = require(string.
	 *
	 * @param      {String}  str     The string
	 * @return     {Uint8Array}  The key = require(string.
	 */
	static getKeyFromStr(str) {
        return Cryptopad.Nacl.util.decodeBase64(str);
	}

	/**
	 * Encrypts a Uint8Array with the given key.
	 *
	 * @param      {<type>}      u8      The u 8
	 * @param      {<type>}      key     The key
	 * @return     {Uint8Array}  The encrypted content.
	 */
	static encrypt(u8, key) {
		const array = u8;
		const nonce = Cryptopad.Nacl.randomBytes(24);
		const packed = Cryptopad.Nacl.secretbox(array, nonce, key);
		if (packed) {
			return new Uint8Array(Cryptopad.slice(nonce).concat(Cryptopad.slice(packed)));
		}
		throw new Error();
	}

	/**
	 * Decrypts a Uint8Array with the given key.
	 *
	 * @param      {Uint8Array}  u8      The u 8
	 * @param      {String}  key     The key
	 * @return     object YOLO
	 */
    static decrypt (u8, key) {
        const Nacl = Cryptopad.Nacl;
        var nonce = Cryptopad.createNonce();
        var i = 0;

        var takeChunk = function () {
            var start = i * cypherChunkLength;
            var end = start + cypherChunkLength;
            i++;
            var box = new Uint8Array(u8.subarray(start, end));

            // decrypt the chunk
            var plaintext = Nacl.secretbox.open(box, nonce, key);
            Cryptopad.increment(nonce);
            return plaintext;
        };

        var buffer = '';
        var res = {
            metadata: undefined,
        };

        // decrypt metadata
        var chunk;
        for (; !res.metadata && i * cypherChunkLength < u8.length;) {
            chunk = takeChunk();
            buffer += Nacl.util.encodeUTF8(chunk);
            try {
                res.metadata = JSON.parse(buffer);
            } catch (e) {
                console.log('buffering another chunk for metadata');
            }
        }

        if (!res.metadata) {
            throw new Error('NO_METADATA');
        }

         var chunks = [];
        // decrypt file contents
        for (;i * cypherChunkLength < u8.length;) {
            chunk = takeChunk();
            if (!chunk) { throw new Error('INVALID_CHUNK'); }
            chunks.push(chunk);
        }

        // send chunks
        res.content = Cryptopad.joinChunks(chunks);

        return res;
    };
}
/**
 * Binds the extern nacl lib to Crypto.
 */
Cryptopad.Nacl = window.nacl;

/**
 * Class for data manager.
 *
 * @class      DataManager (name)
 */
class DataManager {
	/**
	 * Gets the array buffer = require(a source url.
	 *
	 * @param      {<type>}  url     The url
	 * @return     {<type>}  The array buffer.
	 */
	static getArrayBuffer(url) {
		return fetch(url)
		.then(response => {
			if (response.ok) {
				return response.arrayBuffer();
			}
			throw new Errors.FetchFails();
		})
		.then(arrayBuffer => arrayBuffer);
	}

	/**
	 * Creates an url.
	 *
	 * @param      {ArrayBuffer}  arrayBuffer  The array buffer
	 * @return     {String}  The url.
	 */
	static createUrl(arrayBuffer) {
		return window.URL.createObjectURL(arrayBuffer);
	}

	/**
	 * Gets the blob url.
	 *
	 * @param      {ArrayBuffer}  data    The data
	 * @param      {String}  mtype   The mtype
	 * @return     {String}  The blob url.
	 */
	static getBlobUrl(data, mtype) {
		return window.URL.createObjectURL(new Blob([data], {
			type: mtype
		}));
	}

	/**
	 * Gets the data url.
	 *
	 * @param      {ArrayBuffer}  data    The data
	 * @param      {string}  mtype   The mtype
	 * @return     {string}  The data url.
	 */
	static getDataUrl(data, mtype) {
		return 'data:' + mtype + ';base64,' + Cryptopad.Nacl.util.encodeBase64(data);
	}
}

function algorithm(mediaObject) {
	const src = mediaObject.getAttribute('src');
	const strKey = mediaObject.getAttribute('data-crypto-key');
	const cryptoKey = Cryptopad.getKeyFromStr(strKey);
	const xhr = new XMLHttpRequest();
	xhr.open('GET', src, true);
	xhr.responseType = 'arraybuffer';
	xhr.onload = () => {
		const arrayBuffer = xhr.response;
		if (arrayBuffer) {
			const u8 = new Uint8Array(arrayBuffer);
			const decrypted = Cryptopad.decrypt(u8, cryptoKey);
            const binStr = decrypted.content;
			const url = DataManager.getBlobUrl(binStr, mediaObject.getMimeType());
			const decryptionEvent = new Event('decryption');
			decryptionEvent.blob = new Blob([binStr], {
				type: mediaObject.getMimeType()
			});
			window.document.dispatchEvent(decryptionEvent);

            if (window.onMediaMetadata) {
                window.onMediaMetadata(decrypted.metadata);
            }
			/**
			 * Modifications applied on mediaObject.
			 * After these modifications the typeCheck
			 * method must return false otherwise the
			 * filter may infinite loop.
			 */
			mediaObject.setAttribute('src', url);
			mediaObject.removeAttribute('data-crypto-key');

			/**
			 * Filters must call chain to try if the
			 * current mediaObject matches other filters.
			 */
			RunningEngine.return(mediaObject);
		}
	};
	xhr.send(null);
}

module.exports = algorithm;
