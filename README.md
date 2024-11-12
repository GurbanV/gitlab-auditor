# GitLab Auditor

An audit tool for GitLab projects to check compliance with internal standards and best practices.

## Features

- Checks for protected branches.
- Analyzes project and group members (number of owners/maintainers).
- Validates the presence of essential files like README.md, LICENSE, and CHANGELOG.md.
- Assesses merge request reviews.
- Inspects CI/CD configurations for security tools (such as semgrep, trivy etc).
- Verifies fixed dependencies.
- Reports on repository health and large files.

## Installation

Clone the repository and install the requirements:

```bash
git clone https://github.com/GurbanV/gitlab-auditor.git
cd gitlab-auditor
pip install -r requirements.txt
```

## Usage
Set the required environment variables:

```bash
export GITLAB_PRIVATE_TOKEN=your_private_token
export GITLAB_URL=your_gitlab_url
```

## Run

```bash
python audit.py
```

Also supports specifying arguments:

```bash
python audit.py --output markdown --exclude large_files
```

## Requirements
- Python 3.x
- See requirements.txt for Python package dependencies.

## License
This project is licensed under the MIT License.
