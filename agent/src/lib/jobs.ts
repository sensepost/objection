import { IJob } from "./interfaces";

export class Jobs {

    private jobs: IJob[] = [];

    get identifier(): string {
        return Math.random().toString(36).substring(2, 15);
    }

    public add(ident: string, invocation: InvocationListener[], desc: string = ""): void {
        this.jobs.push({ identifier: ident, invocations: invocation , extra: desc});
    }

    public all(): IJob[] {
        return this.jobs;
    }

    public kill(ident: string): boolean {

        this.jobs.forEach((job) => {

            if (job.identifier === ident) {

                // detach any invocations
                job.invocations.forEach((invocation) => {
                    invocation.detach();
                });

                // remove the job from the current jobs
                this.jobs = this.jobs.filter((j) => {
                    return j.identifier !== job.identifier;
                });
            }
        });

        return true;
    }
}
