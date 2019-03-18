import * as fs from "fs";
import { hexStringToBytes } from "../lib/helpers";
import { getNSFileManager } from "./lib/helpers";
import { IIosFilePath, IIosFileSystem } from "./lib/interfaces";
import { NSDictionary, NSFileManager, NSString } from "./lib/types";

const { NSString } = ObjC.classes;

export namespace iosfilesystem {

  // a resolved nsfilemanager instance
  let fileManager: NSFileManager;

  const getFileManager = (): NSFileManager => {
    if (fileManager === undefined) {
      fileManager = getNSFileManager();
      return fileManager;
    }

    return fileManager;
  };

  export const exists = (path: string): boolean => {
    // -- Sample Objective-C
    //
    // NSFileManager *fm = [NSFileManager defaultManager];
    // if ([fm fileExistsAtPath:@"/"]) {
    //     NSLog(@"Yep!");
    // }

    const fm: NSFileManager = getFileManager();
    const p = NSString.stringWithString_(path);

    return fm.fileExistsAtPath_(p);
  };

  export const readable = (path: string): boolean => {
    // -- Sample Objective-C
    //
    // NSFileManager *fm = [NSFileManager defaultManager];
    // NSLog(@"%d / readable?", [fm isReadableFileAtPath:@"/"]);

    const fm: NSFileManager = getFileManager();
    const p = NSString.stringWithString_(path);

    return fm.isReadableFileAtPath_(p);
  };

  export const writable = (path: string): boolean => {
    // -- Sample Objective-C
    //
    // NSFileManager *fm = [NSFileManager defaultManager];
    // NSLog(@"%d / readable?", [fm isReadableFileAtPath:@"/"]);

    const fm: NSFileManager = getFileManager();
    const p = NSString.stringWithString_(path);

    return fm.isWritableFileAtPath_(p);
  };

  export const pathIsFile = (path: string): boolean => {
    const fm: NSFileManager = getFileManager();

    const isDir: NativePointer = Memory.alloc(Process.pointerSize);
    fm.fileExistsAtPath_isDirectory_(path, isDir);

    // deref the isDir pointer to get the bool
    // *isDir === 1 means the path is a directory
    return isDir.readInt() === 0;
  };

  // returns a 'pwd' that assumes the current bundle's path
  // is the directory we are interested in. the handling of
  // pwd is actually handled in the python world and this
  // method is only really called as a starting point.
  export const pwd = (): string => {
    // -- Sample Objective-C
    //
    // NSURL *bundleURL = [[NSBundle mainBundle] bundleURL];

    const NSBundle = ObjC.classes.NSBundle;
    return NSBundle.mainBundle().bundlePath().toString();
  };

  // heavy lifting is done in frida-fs here.
  export const readFile = (path: string): Buffer => {
    return fs.readFileSync(path);
  };

  // heavy lifting is done in frida-fs here.
  export const writeFile = (path: string, data: string): void => {
    const writeStream: any = fs.createWriteStream(path);

    writeStream.on("error", (error: Error) => {
      throw error;
    });

    writeStream.write(hexStringToBytes(data));
    writeStream.end();
  };

  export const ls = (path: string): IIosFileSystem => {
    // -- Sample Objective-C
    //
    // NSFileManager *fm = [NSFileManager defaultManager];
    // NSString *bundleURL = [[NSBundle mainBundle] bundlePath];
    // NSArray *contents = [fm contentsOfDirectoryAtPath:bundleURL error:nil];

    // for (id item in contents) {
    //     NSString *p = [[NSString alloc] initWithFormat:@"%@/%@",bundleURL, item];
    //     NSDictionary *attribs = [fm attributesOfItemAtPath:p error:nil];
    //     NSLog(@"%@ - %@", p, attribs);
    // }

    const fm: NSFileManager = getFileManager();
    const p: NSString = NSString.stringWithString_(path);

    const response: IIosFileSystem = {
      files: {},
      path: `${path}`,
      readable: fm.isReadableFileAtPath_(p),
      writable: fm.isWritableFileAtPath_(p),
    };

    // not being able to read the path should leave us bailing early
    if (!response.readable) { return response; }

    const pathContents: NSDictionary = fm.contentsOfDirectoryAtPath_error_(path, NULL);
    const fileCount: number = pathContents.count();

    // loop-de-loop files
    for (let i = 0; i < fileCount; i++) {

      // pick a file off contents
      const file: string = pathContents.objectAtIndex_(i);

      const pathFileData: IIosFilePath = {
        attributes: {},
        fileName: file.toString(),
        readable: undefined,
        writable: undefined,
      };

      // generate a full path to the file
      let currentFilePath = [path, "/", file].join("");
      currentFilePath = NSString.stringWithString_(currentFilePath);

      // check read / write
      pathFileData.readable = fm.isReadableFileAtPath_(currentFilePath);
      pathFileData.writable = fm.isWritableFileAtPath_(currentFilePath);

      // get attributes
      const attributes = fm.attributesOfItemAtPath_error_(currentFilePath, NULL);

      // if we were able to get attributes for the item,
      // append them to those for this file. (example is listing
      // files in / have some that cant have attributes read for :|)
      if (attributes) {

        // loop the attributes and set them in the file_data
        // dictionary
        const enumerator = attributes.keyEnumerator();
        let key;
        // tslint:disable-next-line:no-conditional-assignment
        while ((key = enumerator.nextObject()) !== null) {

          // get attribute data
          const value: any = attributes.objectForKey_(key);
          // add it to the attributes for this item
          pathFileData.attributes[key] = value.toString();
        }
      }

      // finally, add the file to the final response
      response.files[file] = pathFileData;
    }

    return response;
  };
}
