import { NSBundle, NSDictionary, NSFileManager } from "./types";

// small helper functions for iOS based environments

export const isNSKeyedArchived = (data: ArrayBuffer): boolean => {

  const magic: ArrayBuffer = data.slice(0, 8);
  const magicString: string = String.fromCharCode.apply(null, Array.prototype.slice.call(magic));

  // 62 70 6c 69 73 74 30 30
  return magicString === "bplist00";
};

export const unArchiveDataAndGetString = (data: ObjC.Object | any): string => {

  try {

    // tslint:disable-next-line:max-line-length
    // https://developer.apple.com/documentation/foundation/nskeyedunarchiver/1574811-unarchivetoplevelobjectwithdata
    // This one is marked as DEPRECATED, but seems to still be a thing in
    // iOS 12. Ok for now.
    const NSKeyedUnarchiver = ObjC.classes.NSKeyedUnarchiver;
    const unArchivedData: any = NSKeyedUnarchiver.unarchiveTopLevelObjectWithData_error_(data, NULL);

    if (unArchivedData === null) { return `(data unArchive failed for blob type: ${data.$className})`; }

    switch (unArchivedData.$className) {

      case "__NSDictionary":
      case "__NSDictionaryI":
        const dict: NSDictionary = new ObjC.Object(unArchivedData);
        const enumerator = dict.keyEnumerator();
        let key;
        const stringData: string[] = [];

        // tslint:disable-next-line:no-conditional-assignment
        while ((key = enumerator.nextObject()) !== null) {
          const value = dict.objectForKey_(key);
          stringData.push(`${key}: ${value}`);
        }

        return stringData.join(", ");

      default:
        return `(data unArchive error for class: ${unArchivedData.$className})`;
    }

  } catch (e) {
    return data.toString();
  }
};

export const dataToString = (raw: any, o: string = null): string => {

  if (raw === null) { return ""; }

  try {

    const dataObject: ObjC.Object | any = new ObjC.Object(raw);

    switch (dataObject.$className) {
      case "__NSCFData":
        const dataBytes: ArrayBuffer = Memory.readByteArray(dataObject.bytes(), dataObject.length());

        // If we have data that was archived with NSKeyedArchiver, try and undo that.
        if (isNSKeyedArchived(dataBytes)) { return unArchiveDataAndGetString(dataObject); }

        // Otherwise, just read & convert the bytes read to a string.
        return String.fromCharCode.apply(null, Array.prototype.slice.call(dataBytes));

      case "__NSCFNumber":
        return dataObject.integerValue();
      case "NSTaggedPointerString":
      case "__NSDate":
      case "__NSCFString":
      case "__NSTaggedDate":
        return dataObject.toString();

      default:
        return `(could not get string for class: ${dataObject.$className})`;
    }

  } catch (e) {
    return "(failed to decode)";
  }
};

export const getNSFileManager = (): NSFileManager => {

  const NSFM = ObjC.classes.NSFileManager;
  return NSFM.defaultManager();
};

export const getNSMainBundle = (): NSBundle => {

  const bundle = ObjC.classes.NSBundle;
  return bundle.mainBundle();

};
