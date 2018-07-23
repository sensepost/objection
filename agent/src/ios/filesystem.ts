import fs = require("frida-fs");
import { IIosFilePath, IIosFileSystem } from "../lib/ios/interfaces";
import { NSDictionary, NSFileManager, NSString } from "../lib/ios/types";

const { NSFileManager, NSString} = ObjC.classes;

export class IosFilesystem {

    get NSFileManager(): any {

        if (this.fileManager === undefined) {
            this.fileManager = NSFileManager.defaultManager();
        }

        return this.fileManager;
    }

    // single resolve property for an NSFileManager
    private fileManager: NSFileManager;

    public ls(path: string): any {

        const fm: NSFileManager = this.NSFileManager;
        const p: NSString = NSString.stringWithString_(path);

        const response: IIosFileSystem = {
            files: {},
            path: `${path}`,
            readable: fm.isReadableFileAtPath_(p),
            writable: fm.isWritableFileAtPath_(p),
        };

        // not being able to read the path should leave us bailing early
        if (! response.readable) { return response; }

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
            let currentFilePath = [path, "/", file].join();
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
    }

    public getFile(path: string): any {

        return fs.readFileSync(path);
    }
}
