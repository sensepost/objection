# Contributing to Objection

First off, thanks for taking the time to contribute! 🎉💥

The following are some simple guidelines for contributing to the project. Before you get started though, it is highly recommended that you read the Wiki article entry available [here](https://github.com/sensepost/objection/wiki/Hacking) to get an idea of how the project is put structured and to learn about the various components.

Finally, when submitting your pull request, please try and be as descriptive as possible about what is changing/is fixed. Ideally, including tests greatly helps facilitate this process.

Thanks! 🤘

## Code Structure

Objection consists of two major parts. The Python command line environment and the TypeScript agent. Both of these parts live in this single, monorepo.

- The Python command line lives [here](https://github.com/sensepost/objection/tree/master/objection).
- The TypeScript agent lives [here](https://github.com/sensepost/objection/tree/master/agent).

## Environment Setup

Whether you want to contribute to the TypeScript agent or the Python command line, both components would require some setup.

### Python Command Line

Any Python 3 environment should do, but we recommend you use the latest version of Python. To satisfy all of the dependencies that you may need, install the development dependency group defined in `pyproject.toml`:

```zsh
uv sync --group dev
```

This makes the code dependencies available, along with pytest and other useful development helpers.

To run the test suite, you can then use:

```zsh
uv run pytest
```

or:

```zsh
make test
```

### TypeScript Agent

The objection agent is written using TypeScript 3. It is recommended that you download [Visual Studio Code](https://code.visualstudio.com/) for agent development given the excellent TypeScript support that it has.

For more information on developing for the agent, please see the Wiki article [here](https://github.com/sensepost/objection/wiki/Agent-Development-Environment).
