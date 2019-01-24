import { android } from "./rpc/android";
import { env } from "./rpc/environment";
import { ios } from "./rpc/ios";
import { jobs } from "./rpc/jobs";
import { memory } from "./rpc/memory";
import { version } from "./version";

rpc.exports = {
  ...android,
  ...ios,
  ...env,
  ...jobs,
  ...memory,
  version: () => version,
};
