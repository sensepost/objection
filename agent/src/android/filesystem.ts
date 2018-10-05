import * as fs from "fs";
import { hexStringToBytes } from "../lib/helpers";
import { IAndroidFilesystem } from "./lib/interfaces";
import { getApplicationContext, wrapJavaPerform } from "./lib/libjava";
import { JavaClass } from "./lib/types";

export namespace androidfilesystem {

  export const exists = (path: string): Promise<boolean> => {
    // -- Sample Java
    //
    // File path = new File(".");
    // Boolean e = path.exists();

    return wrapJavaPerform(() => {
      const File: JavaClass = Java.use("java.io.File");
      const file: JavaClass = File.$new(path);

      return file.exists();
    });
  };

  export const readable = (path: string): Promise<boolean> => {
    // -- Sample Java Code
    //
    // File d = new File(".");
    // d.canRead();

    return wrapJavaPerform(() => {
      const File: JavaClass = Java.use("java.io.File");
      const file: JavaClass = File.$new(path);

      return file.canRead();
    });
  };

  export const writable = (path: string): Promise<boolean> => {
    // -- Sample Java Code
    //
    // File d = new File(".");
    // d.canWrite();

    return wrapJavaPerform(() => {
      const File: JavaClass = Java.use("java.io.File");
      const file: JavaClass = File.$new(path);

      return file.canWrite();
    });
  };

  export const pathIsFile = (path: string): Promise<boolean> => {
    // -- Sample Java Code
    //
    // File d = new File(".");
    // d.isFile();

    return wrapJavaPerform(() => {
      const File: JavaClass = Java.use("java.io.File");
      const file: JavaClass = File.$new(path);

      return file.isFile();
    });
  };

  export const pwd = (): Promise<string> => {
    // -- Sample Java
    //
    // getApplicationContext().getFilesDir().getAbsolutePath()

    return wrapJavaPerform(() => {
      const context = getApplicationContext();
      return context.getFilesDir().getAbsolutePath().toString();
    });
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

  export const ls = (p: string): Promise<IAndroidFilesystem> => {
    // -- Sample Java Code
    //
    // File d = new File(".");
    // File[] files = d.listFiles();
    // Log.e(getClass().getName(), "Files: " + files.length);
    // for (int i = 0; i < files.length; i++) {
    //     Log.e(getClass().getName(),
    //             files[i].getName() + ": " + files[i].canRead()
    //             + " " + files[i].lastModified()
    //             + " " + files[i].length()
    //     );
    // }

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
  };
}
