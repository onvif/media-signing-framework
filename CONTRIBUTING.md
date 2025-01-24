# How to make a contribution
This page addresses the guidelines for the following actions below:

- How to clone the repository on your local machine
- How to make a good Pull Request (PR)
- How to post an issue in the issue tracker

## How to clone the repository on your local machine
Please use the following commands to clone the repository on your local machine:

### Fork it from GitHub GUI
Start by [forking the repository](https://docs.github.com/en/github/getting-started-with-github/fork-a-repo)

### Clone it
```sh
git clone https://github.com/<github-username>/signed-media-framework.git
```

### Create your feature branch
```sh
git switch -c <branch-name>
```

### Lint code after adding changes
Run [pre-commit.sh](pre-commit.sh) before committing.
```sh
git add -u && ./pre-commit.sh
```

### Commit your changes
```sh
git commit
```
Follow the conventional commit messages style to write this message.

### Run tests and example applications if possible
It is recommended to run the check tests before pushing your branch. This requires
libcheck installed; See [tests/](./tests/README.md) for more details. 
```sh
./tests/run_check_tests.sh
```

It is further recommended to run the example applications on the available test files.
This requires gStreamer and glib; See [examples/](./examples/README.md) for more details.
```sh
./test_apps.sh
```

It is also recommended to run [valgrind](https://valgrind.org) on the check tests.
```sh
CK_FORK=no valgrind --leak-check=full build/tests/check/unittest_common
CK_FORK=no valgrind --leak-check=full build/tests/check/unittest_signer
CK_FORK=no valgrind --leak-check=full build/tests/check/unittest_validator
```

### Push to the branch
```sh
git push origin <branch-name>
```

### Make a Pull request from GitHub GUI

## How to make a good Pull Request (PR)
Please consider the following guidelines before making a Pull Request:

- Make sure that the code builds perfectly fine and tests pass on your local system.
- It is recommended to run valgrind on the tests, and/or the example applications.
- Follow the [conventional commits](https://www.conventionalcommits.org) message
style in the commit messages.
- The PR will have to meet the code standard already available in the repository.
- Explanatory comments related to code functions are required. Please write code
comments for a better understanding of the code for other developers.

## How to post an issue in the issue tracker
Please supply the following information in the issue:

- The repository version (git tag) where the issue has been found
- If this relates to signing, validation or both
- Error(s) showed during building or running the code
