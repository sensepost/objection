// Execute shell commands on an Android device

var Process = Java.use('java.lang.Process');
var Runtime = Java.use('java.lang.Runtime');
var InputStreamReader = Java.use('java.io.InputStreamReader');
var BufferedReader = Java.use('java.io.BufferedReader');
var StringBuilder = Java.use('java.lang.StringBuilder');

// Run the command
command = Runtime.getRuntime().exec('{{ command }}');

// Read 'stderr'
stderr_input_stream_reader = InputStreamReader.$new(command.getErrorStream());
buffered_reader = BufferedReader.$new(stderr_input_stream_reader);

stderr_string_builder = StringBuilder.$new();
line_buffer = '';

while ((line_buffer = buffered_reader.readLine()) != null) {
    stderr_string_builder.append(line_buffer + '\n');
}

// Read 'stdout'
stdout_input_stream_reader = InputStreamReader.$new(command.getInputStream());
buffered_reader = BufferedReader.$new(stdout_input_stream_reader);

stdout_string_builder = StringBuilder.$new();
line_buffer = '';

while ((line_buffer = buffered_reader.readLine()) != null) {
    stdout_string_builder.append(line_buffer + '\n');
}

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'android-command-exec',
    data: {
        command: '{{ command }}',
        stdout: stdout_string_builder.toString(),
        stderr: stderr_string_builder.toString()
    }
};

send(response);

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
