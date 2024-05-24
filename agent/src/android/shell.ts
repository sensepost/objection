import { IExecutedCommand } from "./lib/interfaces.js";
import { wrapJavaPerform } from "./lib/libjava.js";
import {
  BufferedReader,
  InputStreamReader,
  Runtime,
  StringBuilder
} from "./lib/types.js";


// Executes shell commands on an Android device using Runtime.getRuntime().exec()
export const execute = (cmd: string): Promise<IExecutedCommand> => {
  // -- Sample Java
  //
  // Process command = Runtime.getRuntime().exec("ls -l /");
  // InputStreamReader isr = new InputStreamReader(command.getInputStream());
  // BufferedReader br = new BufferedReader(isr);
  //
  // StringBuilder sb = new StringBuilder();
  // String line = "";
  //
  // while ((line = br.readLine()) != null) {
  //     sb.append(line + "\n");
  // }
  //
  // String output = sb.toString();
  return wrapJavaPerform(() => {

    const runtime: Runtime = Java.use("java.lang.Runtime");
    const inputStreamReader: InputStreamReader = Java.use("java.io.InputStreamReader");
    const bufferedReader: BufferedReader = Java.use("java.io.BufferedReader");
    const stringBuilder: StringBuilder = Java.use("java.lang.StringBuilder");

    // Run the command
    const command = runtime.getRuntime().exec(cmd);

    // Read 'stderr'
    const stdErrInputStreamReader: InputStreamReader = inputStreamReader.$new(command.getErrorStream());
    let bufferedReaderInstance: BufferedReader = bufferedReader.$new(stdErrInputStreamReader);

    const stdErrStringBuilder: StringBuilder = stringBuilder.$new();
    let lineBuffer: string;

    // tslint:disable-next-line:no-conditional-assignment
    while ((lineBuffer = bufferedReaderInstance.readLine()) != null) {
      stdErrStringBuilder.append(lineBuffer + "\n");
    }

    // Read 'stdout'
    const stdOutInputStreamReader: InputStreamReader = inputStreamReader.$new(command.getInputStream());
    bufferedReaderInstance = bufferedReader.$new(stdOutInputStreamReader);

    const stdOutStringBuilder = stringBuilder.$new();
    lineBuffer = "";

    // tslint:disable-next-line:no-conditional-assignment
    while ((lineBuffer = bufferedReaderInstance.readLine()) != null) {
      stdOutStringBuilder.append(lineBuffer + "\n");
    }

    return {
      command: cmd,
      stdErr: stdErrStringBuilder.toString(),
      stdOut: stdOutStringBuilder.toString(),
    };
  });
};
