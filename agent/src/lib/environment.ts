import { getApplicationContext, wrapJavaPerform } from "./android/libjava";
import { DeviceType } from "./constants";
import { IAndroidPackage, IFridaInfo, IIosBundlePaths, IIosPackage } from "./interfaces";
import { NSSearchPaths, NSUserDomainMask } from "./ios/constants";
import { getNSFileManager, getNSMainBundle } from "./ios/helpers";
import { NSBundle } from "./ios/types";

export class Environment {

    public runtime(): string {

        if (ObjC.available) { return DeviceType.IOS; }
        if (Java.available) { return DeviceType.ANDROID; }

        return DeviceType.UNKNOWN;
    }

    public frida(): IFridaInfo {

        return {
            arch: Process.arch,
            debugger: Process.isDebuggerAttached(),
            heap: Frida.heapSize,
            platform: Process.platform,
            version: Frida.version,
        };
    }

    public iosPackage(): IIosPackage {

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

        // -- Sample Objective-C
        //
        // NSFileManager *fm = [NSFileManager defaultManager];
        // NSString *pictures = [[fm URLsForDirectory:NSPicturesDirectory inDomains:NSUserDomainMask] lastObject].path;
        // NSBundle *bundle = [NSBundle mainBundle];
        // NSString *bundlePath = [bundle bundlePath];
        // NSString *receipt = [bundle appStoreReceiptURL].path;
        // NSString *resourcePath = [bundle resourcePath];
    }

    public iosPaths(): IIosBundlePaths {

        const mb: NSBundle = getNSMainBundle();

        return {
            BundlePath: mb.bundlePath().toString(),
            CachesDirectory: this.getPathForNSLocation(NSSearchPaths.NSCachesDirectory),
            DocumentDirectory: this.getPathForNSLocation(NSSearchPaths.NSDocumentDirectory),
            LibraryDirectory: this.getPathForNSLocation(NSSearchPaths.NSLibraryDirectory),
        };
    }

    public androidPackage(): Promise<IAndroidPackage> {

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
    }

    public androidPaths(): any {

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

        // -- Sample Java
        //
        // getApplicationContext().getFilesDir().getAbsolutePath()
    }

    private getPathForNSLocation(NSPath: NSSearchPaths): string {

        const p = getNSFileManager().URLsForDirectory_inDomains_(NSPath, NSUserDomainMask).lastObject();

        if (p) { return p.path().toString(); }

        return "";
    }
}
