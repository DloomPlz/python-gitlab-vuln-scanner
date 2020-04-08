# gitlab_repository_secret_scanner

## Description

It is possible that sensitive data may be present in the code of Gitlab repos (password, sensitive files, etc...) that have been pushed by mistake.
This tool responds to the need to scan Gitlab directories in order to avoid publishing sensitive data.

## Requirements

#### Install dependencies

- You need Python + pip installed (and in $PATH). Install it with : https://www.python.org/downloads/
- Create a virtualenv with `virtualenv venv -p python`.
- Activate the virtualenv with `source venv/bin/activate` for Linux, or `. .\venv\Scripts\activate` for Windows (Powershell).
- Once activated, you can install all needed dependencies for the project : `pip install -r requirements`.

## How to use the tool

- The tool can be launch locally to scan a local repository for secrets, or can be launched during a continuous integration pipeline.

- It is launched with a simple command : `python main.py -l ./path_to_test`

- A test folder has been created to test all the vulnerabilities that can be found by the scanner (declared in the `part.yaml` file).