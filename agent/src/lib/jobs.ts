import { colors as c } from "./color";
import { IJob } from "./interfaces";

export namespace jobs {

  // a record of all of the jobs in the current process
  let currentJobs: IJob[] = [];

  export const identifier = (): string => Math.random().toString(36).substring(2, 15);
  export const all = (): IJob[] => currentJobs;

  export const add = (jobData: IJob): void => {
    currentJobs.push(jobData);
  };

  // determine of a job already exists based on an identifer
  export const hasIdent = (ident: string): boolean => {

    const m: IJob[] = currentJobs.filter((job) => {
      if (job.identifier === ident) {
        return true;
      }
    });

    return m.length > 0;
  };

    // determine of a job already exists based on a type
  export const hasType = (type: string): boolean => {

    const m: IJob[] = currentJobs.filter((job) => {
      if (job.type === type) {
        return true;
      }
    });

    return m.length > 0;
  };

  // kills a job by detatching any invocations and removing
  // the job by identifier
  export const kill = (ident: string): boolean => {
    currentJobs.forEach((job) => {

      if (job.identifier === ident) {

        // detach any invocations
        job.invocations.forEach((invocation) => {
          invocation.detach();
        });

        // remove the job from the current jobs
        currentJobs = currentJobs.filter((j) => {
          return j.identifier !== job.identifier;
        });
      }
    });

    return true;
  };
}
