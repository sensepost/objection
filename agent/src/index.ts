import { android } from "./rpc/android";
import { env } from "./rpc/environment";
import { ios } from "./rpc/ios";
import { jobs } from "./rpc/jobs";
import { version } from "./version";

rpc.exports = {
  ...android,
  ...ios,
  ...env,
  ...jobs,
  version: () => version,
};
