# Release branch secret scan

Result: **PASS**

The release worktree was searched for AWS access-key-shaped strings, GitHub
tokens, OpenAI/Anthropic token patterns, private-key headers, and generated
credential files. No real credential or API key was found.

One manual pattern match is intentional synthetic data in
`backend/tests/test_reachability.py:558`, where a unit test returns a fixed
AWS-shaped string to exercise redaction behavior. The documentation contains
ellipsized credential examples only (`sk-...` and `sk-ant-...`); these are not
credentials.

Gitleaks `8.30.1` was run with `detect --source <release-worktree> --no-git
--redact --exit-code 1` and reported no leaks.
