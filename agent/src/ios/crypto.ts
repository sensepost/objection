import { debug } from "console";
import { colors as c } from "../lib/color";
import { fsend } from "../lib/helpers";
import { IJob } from "../lib/interfaces";
import { jobs } from "../lib/jobs";
import { arrayBufferToHex, hexToString } from "./lib/helpers"

// Encryption algorithms implemented by this module.
const CCAlgorithm = {
  0: { name: "kCCAlgorithmAES128", blocksize: 16 },
  1: { name: "kCCAlgorithmDES", blocksize: 8 },
  2: { name: "kCCAlgorithm3DES", blocksize: 8 },
  3: { name: "kCCAlgorithmCAST", blocksize: 8 },
  4: { name: "kCCAlgorithmRC4", blocksize: 8 },
  5: { name: "kCCAlgorithmRC2", blocksize: 8 }
};

// Encryption algorithms implemented by this module.
const CCOperation = {
  0: "kCCEncrypt",
  1: "kCCDecrypt"
};

// Options flags, passed to CCCryptorCreate().
const CCOption = {
  1: "kCCOptionPKCS7Padding",
  2: "kCCOptionECBMode"
};

// alg for pbkdf. Right now only pbkdf2 is supported by CommonCrypto
const CCPBKDFAlgorithm = {
  2: "kCCPBKDF2"
};

// alg for prt for pbkdf
const CCPseudoRandomAlgorithm = {
  1: "kCCPRFHmacAlgSHA1",
  2: "kCCPRFHmacAlgSHA224",
  3: "kCCPRFHmacAlgSHA256",
  4: "kCCPRFHmacAlgSHA384",
  5: "kCCPRFHmacAlgSHA512"
};

export namespace ioscrypto {

  var cryptoidentifier: string = null

  // operation being performed 0=encrypt 1=decrypt
  var op = 0

  // needed to keep track of CCAlgorithm so we can know 
  // blocksize from CCCryptorCreate to CCCryptorUpdate 
  var alg = 0

  // keep track of all the output bytes.
  // this is necessary because CCCryptorUpdate needs to be 
  // append the final block from CCCryptorFinal
  var dataOutBytes = null

  const secrandomcopybytes = (success: boolean, ident: string): InvocationListener => {
    const hook = "SecRandomCopyBytes"
    return Interceptor.attach(
      Module.getExportByName(null, hook), {
      onEnter: function (args) {

        this.secrandomcopybytes = {}

        this.secrandomcopybytes.rnd = args[0].toInt32()
        this.secrandomcopybytes.count = args[1].toInt32()
        this.bytes = args[2]
      },
      onLeave: function (retval) {
        this.secrandomcopybytes.bytes = arrayBufferToHex(this.bytes.readByteArray(this.secrandomcopybytes.count))

        fsend(ident, hook, this.secrandomcopybytes)
      }
    });
  };

  const cckeyderivationpbkdf = (success: boolean, ident: string): InvocationListener => {
    const hook = "CCKeyDerivationPBKDF"
    return Interceptor.attach(
      Module.getExportByName(null, hook), {
      onEnter: function (args) {

        this.cckeyderivationpbkdf = {}

        // args[0]  "kCCPBKDF2" is the only alg supported by CommonCrypto
        this.cckeyderivationpbkdf.algorithm = CCPBKDFAlgorithm[args[0].toInt32()]

        // args[1]  The text password used as input to the derivation 
        //          function. The actual octets present in this string 
        //          will be used with no additional processing.  It's 
        //          extremely important that the same encoding and 
        //          normalization be used each time this routine is 
        //          called if the same key is  expected to be derived.
        // args[2]  The length of the text password in bytes.
        const passwordPtr = args[1]
        const passwordLen = args[2].toInt32()
        const passwordBytes = arrayBufferToHex(passwordPtr.readByteArray(passwordLen))
        try {
          this.cckeyderivationpbkdf.password = hexToString(passwordBytes)
        } catch {
          this.cckeyderivationpbkdf.password = passwordBytes
        }

        // args[3]  The salt byte values used as input to the derivation function.
        // args[4]  The length of the salt in bytes.
        const saltPtr = args[3]
        const saltLen = args[4].toInt32()
        this.cckeyderivationpbkdf.saltBytes = arrayBufferToHex(saltPtr.readByteArray(saltLen))

        // args[5]  The Pseudo Random Algorithm to use for the derivation iterations.
        this.cckeyderivationpbkdf.prf = CCPseudoRandomAlgorithm[args[5].toInt32()]

        // args[6]  The number of rounds of the Pseudo Random Algorithm to use. 
        this.cckeyderivationpbkdf.rounds = args[6].toInt32()

        // args[7]  The resulting derived key produced by the function.  
        //          The space for this must be provided by the caller. 
        this.derivedKeyPtr = args[7]

        // args[8]  The expected length of the derived key in bytes. 
        this.derivedKeyLen = args[8].toInt32()
      },
      onLeave: function (retval) {
        this.cckeyderivationpbkdf.derivedKey = arrayBufferToHex(this.derivedKeyPtr.readByteArray(this.derivedKeyLen))

        fsend(ident, hook, this.cckeyderivationpbkdf)
      }
    });
  };

  const cccrypt = (success: boolean, ident: string): InvocationListener => {
    const hook = "CCCrypt"
    return Interceptor.attach(
      // Module.getExportByName('libcommonCrypto.dylib', 'CCCrypt'), {
      Module.getExportByName(null, hook), {
      onEnter: function (args) {

        this.cccrpyt = {}

        // args[0]  Defines the basic operation: kCCEncrypt or kCCDecrypt.
        this.op = args[0].toInt32()
        this.cccrpyt.op = CCOperation[this.op]

        // args[1]  Defines the encryption algorithm.
        const alg = args[1].toInt32()
        this.cccrpyt.alg = CCAlgorithm[alg].name

        // args[2]  A word of flags defining options. See discussion for the CCOptions type.
        this.cccrpyt.options = CCOption[args[2].toInt32()]

        // args[3]  Raw key material, length keyLength bytes. 
        // args[4]  Length of key material. Must be appropriate 
        //				  for the select algorithm. Some algorithms may 
        //  				provide for varying key lengths.
        const key = args[3]
        this.cccrpyt.keyLength = args[4].toInt32()
        this.cccrpyt.key = arrayBufferToHex(key.readByteArray(this.cccrpyt.keyLength))

        // args[5]  Initialization vector, optional. Used for 
        //				  Cipher Block Chaining (CBC) mode. If present, 
        //				  must be the same length as the selected 
        //				  algorithm's block size. If CBC mode is
        //				  selected (by the absence of any mode bits in 
        //				  the options	flags) and no IV is present, a 
        //				  NULL (all zeroes) IV will be used. This is 
        //				  ignored if ECB mode is used or if a stream 
        //		  		cipher algorithm is selected. 
        const iv = args[5]
        this.cccrpyt.iv = arrayBufferToHex(iv.readByteArray(CCAlgorithm[alg].blocksize))

        // args[6]  Data to encrypt or decrypt, length dataInLength bytes.
        // args[7]  Length of data to encrypt or decrypt.
        const dataInPtr = args[6]
        const dataInLength = args[7].toInt32()
        const dataInHex = arrayBufferToHex(dataInPtr.readByteArray(dataInLength))
        this.cccrpyt.dataIn = this.op ? dataInHex : hexToString(dataInHex)

        // args[8]  Result is written here. Allocated by caller. 
        //          Encryption and decryption can be performed
        //          "in-place", with the same buffer used for 
        //          input and output. 
        this.dataOut = args[8]

        // args[9]  The size of the dataOut buffer in bytes.  
        this.dataOutAvailable = args[9].toInt32()

        // args[10] On successful return, the number of bytes written 
        //          to dataOut. If kCCBufferTooSmall is returned as 
        //          a result of insufficient buffer space being 
        //          provided, the required buffer space is returned
        //          here. 
        this.dataOutMoved = args[10]
      },
      onLeave: function (retval) {
        const dataOutHex = arrayBufferToHex(this.dataOut.readByteArray(this.dataOutAvailable))
        this.cccrpyt.dataOut = this.op ? hexToString(dataOutHex) : dataOutHex

        fsend(ident, hook, this.cccrpyt)
      }
    });
  };

  const cccryptorcreate = (success: boolean, ident: string): InvocationListener => {
    const hook = "CCCryptorCreate"
    return Interceptor.attach(
      Module.getExportByName(null, hook), {
      onEnter: function (args) {

        this.cccryptorcreate = {}

        // args[0]  Defines the basic operation: kCCEncrypt or kCCDecrypt.
        op = args[0].toInt32()
        this.cccryptorcreate.op = CCOperation[op]

        // args[1]  Defines the encryption algorithm.
        alg = args[1].toInt32()
        this.cccryptorcreate.alg = CCAlgorithm[alg].name

        // args[2]  A word of flags defining options. See discussion for the CCOptions type.
        const option = args[2].toInt32()
        this.cccryptorcreate.options = CCOption[option]

        // args[3]  Raw key material, length keyLength bytes. 
        // args[4]  Length of key material. Must be appropriate 
        //				  for the select algorithm. Some algorithms may 
        //  				provide for varying key lengths.
        const keyPtr = args[3]
        this.cccryptorcreate.keyLength = args[4].toInt32()
        this.cccryptorcreate.key = arrayBufferToHex(keyPtr.readByteArray(this.cccryptorcreate.keyLength))

        // args[5]  Initialization vector, optional. Used for 
        //				  Cipher Block Chaining (CBC) mode. If present, 
        //				  must be the same length as the selected 
        //				  algorithm's block size. If CBC mode is
        //				  selected (by the absence of any mode bits in 
        //				  the options	flags) and no IV is present, a 
        //				  NULL (all zeroes) IV will be used. This is 
        //				  ignored if ECB mode is used or if a stream 
        //		  		cipher algorithm is selected. 
        const ivPtr = args[5]
        this.cccryptorcreate.iv = arrayBufferToHex(ivPtr.readByteArray(CCAlgorithm[alg].blocksize))
      },
      onLeave: function (retval) {
        fsend(ident, hook, this.cccryptorcreate)
      }
    });
  };

  const cccryptorupdate = (success: boolean, ident: string): InvocationListener => {
    const hook = "CCCryptorUpdate"
    return Interceptor.attach(
      Module.getExportByName(null, hook), {
      onEnter: function (args) {
        this.cccryptorupdate = {}

        // reset for the next operation. 
        dataOutBytes = ""

        // args[1]  Data to process, length dataInLength bytes.
        const dataInPtr = args[1]

        // args[2]  Length of data to process.
        this.dataInLength = args[2].toInt32()
        this.cccryptorupdate.dataInLength = this.dataInLength

        // args[3]  Result is written here. Allocated by caller. 
        //	  		  Encryption and decryption can be performed
        //				  "in-place", with the same buffer used for 
        //				  input and output. 
        this.dataOutPtr = args[3]

        // args[4]  The size of the dataOut buffer in bytes.
        this.dataOutAvailable = args[4].toInt32()
        this.cccryptorupdate.dataOutAvailable = this.dataOutAvailable

        const dataIn = arrayBufferToHex(dataInPtr.readByteArray(this.dataInLength))
        this.cccryptorupdate.dataIn = op ? dataIn : hexToString(dataIn)
      },
      onLeave: function (retval) {
        const blocksize = CCAlgorithm[alg].blocksize
        // if the messsage is longer than 1 block then we need to 
        // remember everything before the final block
        if (this.dataInLength > blocksize) {
          dataOutBytes = arrayBufferToHex(this.dataOutPtr.readByteArray(this.dataOutAvailable)).split("00")[0]

          // TODO: There is sometimes padding added to the end of this message
          // someone please fix this in a pull request. it is super hacky.
          this.cccryptorupdate.dataOut = dataOutBytes.split("000000")[0]
        }

        fsend(ident, hook, this.cccryptorupdate)
      }
    });
  };

  const cccryptorfinal = (success: boolean, ident: string): InvocationListener => {
    const hook = "CCCryptorFinal"
    return Interceptor.attach(
      Module.getExportByName(null, hook), {
      onEnter: function (args) {

        this.cccryptorfinal = {}

        // args[1]  Result is written here. Allocated by caller. 
        //	  		  Encryption and decryption can be performed
        //				  "in-place", with the same buffer used for 
        //				  input and output. 
        this.dataOutPtr = args[1]

        // args[2]  The size of the dataOut buffer in bytes.
        this.dataOutAvailable = args[2].toInt32()
      },
      onLeave: function (retval) {
        // var dataOutHex = arrayBufferToHex(this.dataOutPtr.readByteArray(this.dataOutAvailable))
        // this.cccryptorfinal.dataOut = op ? hexToString(dataOutHex) : dataOutHex
        
        // append the final block the any previous blocks that might exist
        dataOutBytes += arrayBufferToHex(this.dataOutPtr.readByteArray(this.dataOutAvailable))
        this.cccryptorfinal.dataOut = dataOutBytes

        fsend(ident, hook, this.cccryptorfinal)
      }
    });
  };

  export const disable = (): void => {
    // if we already have a job registered then kill it
    if (jobs.hasIdent(cryptoidentifier)) {
      send(c.red(`Killing `) + `${cryptoidentifier}`)
      jobs.kill(cryptoidentifier)
    }
  };

  export const monitor = (): void => {
    // if we already have a job registered then return
    if (jobs.hasIdent(cryptoidentifier)) {
      send(`${c.greenBright("Job already registered")}: ${c.blueBright(cryptoidentifier)}`)
      return
    }

    const job: IJob = {
      identifier: jobs.identifier(),
      invocations: [],
      type: "ios-crypto-monitor",
    };

    cryptoidentifier = job.identifier

    job.invocations.push(secrandomcopybytes(true, job.identifier));
    job.invocations.push(cckeyderivationpbkdf(true, job.identifier));
    job.invocations.push(cccrypt(true, job.identifier));
    job.invocations.push(cccryptorcreate(true, job.identifier));
    job.invocations.push(cccryptorupdate(true, job.identifier));
    job.invocations.push(cccryptorfinal(true, job.identifier));

    jobs.add(job);
  };
}