import { getApplicationContext, wrapJavaPerform } from "../android/lib/libjava";
import { NSSearchPaths, NSUserDomainMask } from "../ios/lib/constants";
import { getNSFileManager, getNSMainBundle } from "../ios/lib/helpers";
import { NSBundle } from "../ios/lib/types";
import { DeviceType } from "../lib/constants";
import { IAndroidPackage, IFridaInfo, IIosBundlePaths, IIosPackage } from "../lib/interfaces";

export namespace environment {

  // small helper function to lookup ios bundle paths
  const getPathForNSLocation = (NSPath: NSSearchPaths): string => {

    const p = getNSFileManager().URLsForDirectory_inDomains_(NSPath, NSUserDomainMask).lastObject();

    if (p) {
      return p.path().toString();
    }

    return "";
  };

  export const runtime = (): string => {

    if (ObjC.available) { return DeviceType.IOS; }
    if (Java.available) { return DeviceType.ANDROID; }

    return DeviceType.UNKNOWN;
  };

  export const frida = (): IFridaInfo => {

    return {
      arch: Process.arch,
      debugger: Process.isDebuggerAttached(),
      heap: Frida.heapSize,
      platform: Process.platform,
      version: Frida.version,
    };
  };

  export const iosPackage = (): IIosPackage => {

    // -- Sample Objective-C
    //
    // NSFileManager *fm = [NSFileManager defaultManager];
    // NSString *pictures = [[fm URLsForDirectory:NSPicturesDirectory inDomains:NSUserDomainMask] lastObject].path;
    // NSBundle *bundle = [NSBundle mainBundle];
    // NSString *bundlePath = [bundle bundlePath];
    // NSString *receipt = [bundle appStoreReceiptURL].path;
    // NSString *resourcePath = [bundle resourcePath];

    const { UIDevice } = ObjC.classes;
    const mb: NSBundle = getNSMainBundle();

    return {
      applicationName: mb.objectForInfoDictionaryKey_("CFBundleIdentifier").toString(),
      deviceName: UIDevice.currentDevice().name().toString(),
      identifierForVendor: UIDevice.currentDevice().identifierForVendor().toString(),
      model: UIDevice.currentDevice().model().toString(),
      systemName: UIDevice.currentDevice().systemName().toString(),
      systemVersion: UIDevice.currentDevice().systemVersion().toString(),
    };
  };

  export const iosPaths = (): IIosBundlePaths => {

    const mb: NSBundle = getNSMainBundle();

    return {
      BundlePath: mb.bundlePath().toString(),
      CachesDirectory: getPathForNSLocation(NSSearchPaths.NSCachesDirectory),
      DocumentDirectory: getPathForNSLocation(NSSearchPaths.NSDocumentDirectory),
      LibraryDirectory: getPathForNSLocation(NSSearchPaths.NSLibraryDirectory),
    };
  };

  export const androidPackage = (): Promise<IAndroidPackage> => {

    return wrapJavaPerform(() => {

      // https://developer.android.com/reference/android/os/Build.html
      const Build: any = Java.use("android.os.Build");

      return {
        application_name: getApplicationContext().getPackageName(),
        board: Build.BOARD.value.toString(),
        brand: Build.BRAND.value.toString(),
        device: Build.DEVICE.value.toString(),
        host: Build.HOST.value.toString(),
        id: Build.ID.value.toString(),
        model: Build.MODEL.value.toString(),
        product: Build.PRODUCT.value.toString(),
        user: Build.USER.value.toString(),
        version: Java.androidVersion,
      };
    });
  };

  export const androidPaths = (): Promise<any> => {

    // -- Sample Java
    //
    // getApplicationContext().getFilesDir().getAbsolutePath()

    return wrapJavaPerform(() => {

      const context = getApplicationContext();

      return {
        cacheDirectory: context.getCacheDir().getAbsolutePath().toString(),
        codeCacheDirectory: "getCodeCacheDir" in context ? context.getCodeCacheDir()
          .getAbsolutePath().toString() : "n/a",
        externalCacheDirectory: context.getExternalCacheDir().getAbsolutePath().toString(),
        filesDirectory: context.getFilesDir().getAbsolutePath().toString(),
        obbDir: context.getObbDir().getAbsolutePath().toString(),
        packageCodePath: context.getPackageCodePath().toString(),
      };
    });
  };
}
