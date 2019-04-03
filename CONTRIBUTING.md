# Contributing to Objection

First off, thanks for taking the time to contribute! 🎉💥

The following is some simple guidelines for contributing to the project. Before you get started though, it is highly recommended that you read the Wiki article entry available [here](https://github.com/sensepost/objection/wiki/Hacking) to get an idea of how the project is put structured and to learn about the various components.

Finally, when submitting your pull request, please try and be as descriptive as possible about what is changing/is fixed. Ideally, including tests greatly helps fascilitate this process.

Thanks! 🤘

## Code Structure

Objection consists of two major parts. The Python command line environment and the TypeScript agent. Both of these parts live in this single, monorepo.

- The Python command line lives [here](https://github.com/sensepost/objection/tree/master/objection).
- The TypeScript agent lives [here](https://github.com/sensepost/objection/tree/master/agent).

## Environment Setup

Wether you want to contribute to the TypeScript agent or the Python command line, both components would require some setup.

### Python Command Line

Any Python 3 environment should do, but we recommend you use the latest version of Python. To satisfy all of the dependencies that you may need, install those defined in the [`requirements-dev.txt`](https://github.com/sensepost/objection/blob/master/requirements-dev.txt) file in the projects root. This would make all of the code dependencies available, as well as some useful debugging helpers.

### TypeScript Agent

The objection agent is written using TypeScript 3. It is recommended that you download [Visual Studio Code](https://code.visualstudio.com/) for agent development given the excellent TypeScript support that it has.

For more information on developing for the agent, please see the Wiki article [here](https://github.com/sensepost/objection/wiki/Agent-Development-Environment).
