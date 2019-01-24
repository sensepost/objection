import { jobs as j } from "../lib/jobs";

export const jobs = {
  // jobs
  jobsGet: () => j.all(),
  jobsKill: (ident: string) => j.kill(ident),
};
