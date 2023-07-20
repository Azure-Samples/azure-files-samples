# Git Hooks
- The hooks need to be enabled manually by the contributor.
- To enable hooks, change the default hook directory by `git config core.hooksPath .githooks` or manually copy hooks from `.githooks` to `.git/hooks`
- New validations can be added to `.githooks/pre-commit`.


# GitHub Actions
- Github actions are stored in .github/workflow
- To modify automatic packaging process (for cifs and nfs diagnostic scripts), make changes to `.github/workflow/packaging-action.yaml`
- New validations can be added here.
