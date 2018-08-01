import { IAndroidFilesystem } from "./lib/interfaces";
import { wrapJavaPerform } from "./lib/libjava";
import { JavaClass } from "./lib/types";

export class AndroidFilesystem {

  public ls(p: string): Promise<IAndroidFilesystem> {

    return wrapJavaPerform(() => {

      const File: JavaClass = Java.use("java.io.File");
      const directory: JavaClass = File.$new(p);

      const response: IAndroidFilesystem = {
        files: {},
        path: p,
        readable: directory.canRead(),
        writable: directory.canWrite(),
      };

      if (!response.readable) { return response; }

      // get a listing of the files in the directory
      const files: any[] = directory.listFiles();

      for (const file of files) {
        response.files[file.getName()] = {
          attributes: {
            isDirectory: file.isDirectory(),
            isFile: file.isFile(),
            isHidden: file.isHidden(),
            lastModified: file.lastModified(),
            size: file.length(),
          },
          fileName: file.getName(),
          readable: file.canRead(),
          writable: file.canWrite(),
        };
      }

      return response;

    });
  }
}
