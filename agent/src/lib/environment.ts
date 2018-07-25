import { getApplicationContext } from "./android/libjava";
import { DeviceType } from "./enums";
import { IAndroidPackage, IFridaInfo, IIosPackage } from "./interfaces";

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
            platform: Process.platform,
            version: Frida.version,
        };
    }

    public ios(): IIosPackage {

        const { UIDevice, NSBundle } = ObjC.classes;

        return {
            applicationName: NSBundle.mainBundle().objectForInfoDictionaryKey_("CFBundleIdentifier").toString(),
            deviceName: UIDevice.currentDevice().name().toString(),
            identifierForVendor: UIDevice.currentDevice().identifierForVendor().toString(),
            model: UIDevice.currentDevice().model().toString(),
            systemName: UIDevice.currentDevice().systemName().toString(),
            systemVersion: UIDevice.currentDevice().systemVersion().toString(),
        };
    }

    public android(): Promise<IAndroidPackage> {

        return new Promise((resolve, reject) => {

            Java.perform(() => {

                try {

                    // https://developer.android.com/reference/android/os/Build.html
                    const Build: any = Java.use("android.os.Build");

                    const result = {
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

                    resolve(result);

                } catch (e) {

                    reject(e);
                }
            });
        });
    }
}
