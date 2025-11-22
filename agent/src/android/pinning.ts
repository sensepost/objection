import { colors as c } from "../lib/color.js";
import { qsend } from "../lib/helpers.js";
import * as jobs from "../lib/jobs.js";
import {
  wrapJavaPerform,
  Java
} from "./lib/libjava.js";
import {
  ArrayList,
  CertificatePinner,
  PinningTrustManager,
  SSLCertificateChecker,
  SSLContext,
  TrustManagerImpl,
  X509TrustManager,
} from "./lib/types.js";


// a simple flag to control if we should be quiet or not
let quiet: boolean = false;

const sslContextEmptyTrustManager = (ident: number): Promise<any> => {
  // -- Sample Java
  //
  // "Generic" TrustManager Example
  //
  // TrustManager[] trustAllCerts = new TrustManager[] {
  //     new X509TrustManager() {
  //         public java.security.cert.X509Certificate[] getAcceptedIssuers() {
  //             return null;
  //         }
  //         public void checkClientTrusted(X509Certificate[] certs, String authType) {  }
  //         public void checkServerTrusted(X509Certificate[] certs, String authType) {  }
  //     }
  // };
  // SSLContext sslcontect = SSLContext.getInstance("TLS");
  // sslcontect.init(null, trustAllCerts, null);
  return wrapJavaPerform(() => {
    const x509TrustManager: X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    const sSLContext: SSLContext = Java.use("javax.net.ssl.SSLContext");

    // Some 'anti-frida' detections will scan /proc/<pid>/maps.
    // Rename the tempFileNaming prefix as this could end up in maps.
    // https://github.com/frida/frida-java-bridge/blob/8b3790f7489ff5be7b19ddaccf5149d4e7738460/lib/class-factory.js#L94
    if (Java.classFactory.tempFileNaming.prefix == 'frida') {
      Java.classFactory.tempFileNaming.prefix = 'onetwothree';
    }

    // Implement a new TrustManager
    // ref: https://gist.github.com/oleavr/3ca67a173ff7d207c6b8c3b0ca65a9d8
    const TrustManager: X509TrustManager = Java.registerClass({
      implements: [x509TrustManager],
      methods: {
        // tslint:disable-next-line:no-empty
        checkClientTrusted(chain, authType) { },
        // tslint:disable-next-line:no-empty
        checkServerTrusted(chain, authType) { },
        getAcceptedIssuers() {
          return [];
        },
      },
      name: "com.sensepost.test.TrustManager",
    });

    // Prepare the TrustManagers array to pass to SSLContext.init()
    const TrustManagers: X509TrustManager[] = [TrustManager.$new()];
    send(c.blackBright("Custom TrustManager ready, overriding SSLContext.init()"));

    // Get a handle on the init() on the SSLContext class
    const SSLContextInit = sSLContext.init.overload(
      "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");

    // Override the init method, specifying our new TrustManager
    SSLContextInit.implementation = function (keyManager, trustManager, secureRandom) {
      qsend(quiet,
        c.blackBright(`[${ident}] `) + `Called ` +
        c.green(`SSLContext.init()`) +
        `, overriding TrustManager with empty one.`,
      );

      SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
    };

    return SSLContextInit;
  });
};

const okHttp3CertificatePinnerCheck = (ident: number): Promise<any | undefined> => {
  // -- Sample Java
  //
  // Example used to test this bypass.
  //
  // String hostname = "swapi.co";
  // CertificatePinner certificatePinner = new CertificatePinner.Builder()
  //         .add(hostname, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
  //         .build();
  // OkHttpClient client = new OkHttpClient.Builder()
  //         .certificatePinner(certificatePinner)
  //         .build();
  // Request request = new Request.Builder()
  //         .url("https://swapi.co/api/people/1")
  //         .build();
  // Response response = client.newCall(request).execute();
  return wrapJavaPerform(() => {
    try {
      const certificatePinner: CertificatePinner = Java.use("okhttp3.CertificatePinner");
      send(c.blackBright(`Found okhttp3.CertificatePinner, overriding CertificatePinner.check()`));

      if(!certificatePinner.check) {
        return null;
      }

      const CertificatePinnerCheck = certificatePinner.check.overload("java.lang.String", "java.util.List");

      // tslint:disable-next-line:only-arrow-functions
      CertificatePinnerCheck.implementation = function () {
        qsend(quiet,
          c.blackBright(`[${ident}] `) + `Called ` +
          c.green(`OkHTTP 3.x CertificatePinner.check()`) +
          `, not throwing an exception.`,
        );
      };

      return CertificatePinnerCheck;

    } catch (err) {
      if ((err as Error).message.indexOf("java.lang.ClassNotFoundException") !== 0) {
        throw err;
      }
      return null;
    }
  });
};

const okHttp3CertificatePinnerCheckOkHttp = (ident: number): Promise<any | undefined> => {
  // -- Sample Java
  //
  // Example used to test this bypass.
  //
  // String hostname = "swapi.co";
  // CertificatePinner certificatePinner = new CertificatePinner.Builder()
  //         .add(hostname, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
  //         .build();
  // OkHttpClient client = new OkHttpClient.Builder()
  //         .certificatePinner(certificatePinner)
  //         .build();
  // Request request = new Request.Builder()
  //         .url("https://swapi.co/api/people/1")
  //         .build();
  // Response response = client.newCall(request).execute();
  return wrapJavaPerform(() => {
    try {
      const certificatePinner: CertificatePinner = Java.use("okhttp3.CertificatePinner");

      if(!certificatePinner.check$okhttp) {
        return null;
      }
      
      send(c.blackBright(`Found okhttp3.CertificatePinner, overriding CertificatePinner.check$okhttp()`));

      const CertificatePinnerCheckOkHttp = certificatePinner.check$okhttp.overload("java.lang.String", "u15");

      // tslint:disable-next-line:only-arrow-functions
      CertificatePinnerCheckOkHttp.implementation = function () {
        qsend(quiet,
          c.blackBright(`[${ident}] `) + `Called check$okhttp ` +
          c.green(`OkHTTP 3.x CertificatePinner.check$okhttp()`) +
          `, not throwing an exception.`,
        );
      };

      return CertificatePinnerCheckOkHttp;

    } catch (err) {
      if ((err as Error).message.indexOf("java.lang.ClassNotFoundException") !== 0) {
        throw err;
      }
      return null;
    }
  });
};

const appceleratorTitaniumPinningTrustManager = (ident: number): Promise<any | undefined> => {
  return wrapJavaPerform(() => {
    try {
      const pinningTrustManager: PinningTrustManager = Java.use("appcelerator.https.PinningTrustManager");
      const PinningTrustManagerCheckServerTrusted = pinningTrustManager.checkServerTrusted;

      if(!PinningTrustManagerCheckServerTrusted) {
        return null;
      }

      send(
        c.blackBright(`Found appcelerator.https.PinningTrustManager, ` +
          `overriding PinningTrustManager.checkServerTrusted()`),
      );


      // tslint:disable-next-line:only-arrow-functions
      PinningTrustManagerCheckServerTrusted.implementation = function () {
        qsend(quiet,
          c.blackBright(`[${ident}] `) + `Called ` +
          c.green(`PinningTrustManager.checkServerTrusted()`) +
          `, not throwing an exception.`,
        );
      };

      return PinningTrustManagerCheckServerTrusted;

    } catch (err) {
      if ((err as Error).message.indexOf("java.lang.ClassNotFoundException") !== 0) {
        throw err;
      }
      return null;
    }
  });
};

// Android 7+ TrustManagerImpl.verifyChain()
// The work in the following NCC blog post was a great help for this hook!
// hattip @AdriVillaB :)
// https://www.nccgroup.trust/uk/about-us/newsroom-and-events/
//  blogs/2017/november/bypassing-androids-network-security-configuration/
//
// More information: https://sensepost.com/blog/2018/tip-toeing-past-android-7s-network-security-configuration/
const trustManagerImplVerifyChainCheck = (ident: number): Promise<any> => {
  return wrapJavaPerform(() => {
    try {
      const trustManagerImpl: TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");

      // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/
      //  platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650
      const TrustManagerImplverifyChain = trustManagerImpl.verifyChain;

      if((!TrustManagerImplverifyChain)) {
        return null;
      }

       send(
        c.blackBright(`Found com.android.org.conscrypt.TrustManagerImpl, ` +
          `overriding TrustManagerImpl.verifyChain()`),
      );


      // tslint:disable-next-line:only-arrow-functions
      TrustManagerImplverifyChain.implementation = function (untrustedChain, trustAnchorChain,
        host, clientAuth, ocspData, tlsSctData) {
        qsend(quiet,
          c.blackBright(`[${ident}] `) + `Called (Android 7+) ` +
          c.green(`TrustManagerImpl.verifyChain()`) + `, not throwing an exception.`,
        );

        // Skip all the logic and just return the chain again :P
        return untrustedChain;
      };

      return TrustManagerImplverifyChain;

    } catch (err) {
      if ((err as Error).message.indexOf("java.lang.ClassNotFoundException") !== 0) {
        throw err;
      }
      return null;
    }
  });
};

// Android 7+ TrustManagerImpl.checkTrustedRecursive()
// The work in the following method is based on:
// https://techblog.mediaservice.net/2018/11/universal-android-ssl-pinning-bypass-2/
const trustManagerImplCheckTrustedRecursiveCheck = (ident: number): Promise<any> => {
  return wrapJavaPerform(() => {
    try {
      const arrayList: ArrayList = Java.use("java.util.ArrayList");
      const trustManagerImpl: TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
      
      if(!trustManagerImpl.checkTrustedRecursive) {
        return null;
      }

      // https://android.googlesource.com/platform/external/conscrypt/+/1186465/src/
      //  platform/java/org/conscrypt/TrustManagerImpl.java#391
      const TrustManagerImplcheckTrustedRecursive = trustManagerImpl.checkTrustedRecursive;
      send(
        c.blackBright(`Found com.android.org.conscrypt.TrustManagerImpl, ` +
          `overriding TrustManagerImpl.checkTrustedRecursive()`),
      );

      // tslint:disable-next-line:only-arrow-functions
      TrustManagerImplcheckTrustedRecursive.implementation = function (certs, host, clientAuth, untrustedChain,
        trustAnchorChain, used) {
        qsend(quiet,
          c.blackBright(`[${ident}] `) + `Called (Android 7+) ` +
          c.green(`TrustManagerImpl.checkTrustedRecursive()`) + `, not throwing an exception.`,
        );

        // Return an empty list
        return arrayList.$new();
      };

      return TrustManagerImplcheckTrustedRecursive;

    } catch (err) {
      if ((err as Error).message.indexOf("java.lang.ClassNotFoundException") !== 0) {
        throw err;
      }
      return null;
    }
  });
};

const phoneGapSSLCertificateChecker = (ident: number): Promise<any> => {
  return wrapJavaPerform(() => {
    try {
      const sslCertificateChecker: SSLCertificateChecker = Java.use("nl.xservices.plugins.SSLCertificateChecker");

      if(!sslCertificateChecker.execute) {
        return null;
      }
      
      send(
        c.blackBright(`Found nl.xservices.plugins.SSLCertificateChecker, ` +
          `overriding SSLCertificateChecker.execute()`),
      );

      const SSLCertificateCheckerExecute = sslCertificateChecker.execute.overload("java.lang.String", 
        "org.json.JSONArray", "org.apache.cordova.CallbackContext");

      SSLCertificateCheckerExecute.implementation = function (str, jsonArray, callBackContext) {
        qsend(quiet,
          c.blackBright(`[${ident}] `) + `Called ` +
          c.green(`SSLCertificateChecker.execute()`) +
          `, not throwing an exception.`,
        );
        callBackContext.success("CONNECTION_SECURE");
        return true;
      };

      return SSLCertificateCheckerExecute;

    } catch (err) {
      if ((err as Error).message.indexOf("java.lang.ClassNotFoundException") !== 0) {
        throw err;
      }
      return null;
    }
  });
};

// the main exported function to run all of the pinning bypass methods known
export const disable = async (q: boolean): Promise<void> => {
  if (q) {
    send(c.yellow(`Quiet mode enabled. Not reporting invocations.`));
    quiet = true;
  }

  const job: jobs.Job = new jobs.Job(jobs.identifier(), "android-sslpinning-disable");
  
  job.addImplementation(await sslContextEmptyTrustManager(job.identifier));
  // Exceptions can cause undefined values if classes are not found. Thus addImplementation only adds if function was hooked
  job.addImplementation(await okHttp3CertificatePinnerCheck(job.identifier));
  job.addImplementation(await okHttp3CertificatePinnerCheckOkHttp(job.identifier));
  job.addImplementation(await appceleratorTitaniumPinningTrustManager(job.identifier));
  job.addImplementation(await trustManagerImplVerifyChainCheck(job.identifier));
  job.addImplementation(await trustManagerImplCheckTrustedRecursiveCheck(job.identifier));
  job.addImplementation(await phoneGapSSLCertificateChecker(job.identifier));

  jobs.add(job);
};
