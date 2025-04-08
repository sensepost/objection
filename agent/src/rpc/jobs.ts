import * as j from "../lib/jobs.js";

export const jobs = {
  // jobs
  jobsGet: () => j.all(),
  jobsKill: (ident: number) => j.kill(ident),
};
