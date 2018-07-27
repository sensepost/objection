import { NSBundle, NSFileManager } from "./types";

// small helper functions for iOS based environments

export function data_to_string(raw: any): string {

    try {

        const data: any = new ObjC.Object(raw);
        return Memory.readUtf8String(data.bytes(), data.length());

    } catch (_) {

        try {
            return raw.toString();

        } catch (__) {
            return "";
        }
    }
}

export const getNSFileManager = (): NSFileManager => {

    const NSFM  = ObjC.classes.NSFileManager;
    return NSFM.defaultManager();
};

export const getNSMainBundle = (): NSBundle => {

    const bundle = ObjC.classes.NSBundle;
    return bundle.mainBundle();

};
