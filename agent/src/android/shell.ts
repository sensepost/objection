import { IExecutedCommand } from "./lib/interfaces";
import { wrapJavaPerform } from "./lib/libjava";
import { JavaClass } from "./lib/types";

export namespace androidshell {

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

      const Runtime: JavaClass = Java.use("java.lang.Runtime");
      const InputStreamReader: JavaClass = Java.use("java.io.InputStreamReader");
      const BufferedReader: JavaClass = Java.use("java.io.BufferedReader");
      const StringBuilder: JavaClass = Java.use("java.lang.StringBuilder");

      // Run the command
      const command = Runtime.getRuntime().exec(cmd);

      // Read 'stderr'
      const stdErrInputStreamReader: JavaClass = InputStreamReader.$new(command.getErrorStream());
      let bufferedReader = BufferedReader.$new(stdErrInputStreamReader);

      const stdErrStringBuilder = StringBuilder.$new();
      let lineBuffer: string;

      // tslint:disable-next-line:no-conditional-assignment
      while ((lineBuffer = bufferedReader.readLine()) != null) {
        stdErrStringBuilder.append(lineBuffer + "\n");
      }

      // Read 'stdout'
      const stdOutInputStreamReader = InputStreamReader.$new(command.getInputStream());
      bufferedReader = BufferedReader.$new(stdOutInputStreamReader);

      const stdOutStringBuilder = StringBuilder.$new();
      lineBuffer = "";

      // tslint:disable-next-line:no-conditional-assignment
      while ((lineBuffer = bufferedReader.readLine()) != null) {
        stdOutStringBuilder.append(lineBuffer + "\n");
      }

      const commandOutput: IExecutedCommand = {
        command: cmd,
        stdErr: stdErrStringBuilder.toString(),
        stdOut: stdOutStringBuilder.toString(),
      };

      return commandOutput;
    });
  };
}
