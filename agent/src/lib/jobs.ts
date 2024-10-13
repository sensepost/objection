import { colors as c } from "./color.js";

export class Job {
  identifier: number;
  private invocations?: InvocationListener[] = [];
  private replacements?: any[] = [];
  private implementations?: any[] = [];
  type: string;

  constructor(identifier: number, type: string) {
    this.identifier = identifier;
    this.type = type;
  }

  addInvocation(invocation: any): void {
    if (invocation === undefined) {
      // c.log(c.redBright(`[warn] Undefined Invocation!`));
      c.log(c.redBright(`[warn] Undefined invocation`));
    }
    if (invocation !== null)
      this.invocations.push(invocation);
    
  }; 
  
  addImplementation(implementation: any): void {
    if (implementation !== undefined)
      this.implementations.push(implementation);
  };
  
  addReplacement(replacement: any): void {
    if (replacement !== undefined)
      this.replacements.push(replacement);
  };

  killAll(): void {
    // remove all invocations
    if (this.invocations && this.invocations.length > 0) {
      this.invocations.forEach((invocation) => {
        (invocation) ? invocation.detach() :
          c.log(c.blackBright(`[warn] Skipping detach on null`));
      });
    }

    // revert any replacements
    if (this.replacements && this.replacements.length > 0) {
      this.replacements.forEach((replacement) => {
        Interceptor.revert(replacement);
      });
    }

    // remove implementation replacements
    if (this.implementations && this.implementations.length > 0) {
      this.implementations.forEach((method) => {
        if (method.implementation == undefined) {
          c.log(c.red(`[warn] ${this.type} job missing implementation value`));
        }
         
        send(c.blackBright(`(`)+ c.blueBright(this.identifier.toString())+ c.blackBright(`) Removing ${method.holder} <function: ${method.methodName}>`))
        
        // TODO: May be racy if the method is currently used.
        method.implementation = null;
      });
    }
  }
}


// a record of all of the jobs in the current process
let currentJobs: Job[] = [];

export const identifier = (): number => Number(Math.random().toString(36).substring(2, 8));
export const all = (): Job[] => currentJobs;

export const add = (jobData: Job): void => {
  send(`Registering job ` + c.blueBright(`${jobData.identifier}`) +
    `. Name: ` + c.greenBright(`${jobData.type}`));
  currentJobs.push(jobData);
};

// determine of a job already exists based on an identifier
export const hasIdent = (ident: number): boolean => {

  const m: Job[] = currentJobs.filter((job) => {
    if (job.identifier === ident) {
      return true;
    }
  });

  return m.length > 0;
};

// determine if a job already exists based on a type
export const hasType = (type: string): boolean => {

  const m: Job[] = currentJobs.filter((job) => {
    if (job.type === type) {
      return true;
    }
  });

  return m.length > 0;
};

// kills a job by detaching any invocations and removing
// the job by identifier
export const kill = (ident: number): boolean => {
  currentJobs.forEach((job) => {

    if (job.identifier !== ident) return;

    send(`Killing job ` + c.blueBright(`${job.identifier}`) +
    `. Name: ` + c.greenBright(`${job.type}`));

    // remove any hooks
    job.killAll();
    
    // remove the job from the current jobs
    currentJobs = currentJobs.filter((j) => {
      return j.identifier !== job.identifier;
    });

  });

  return true;
};
