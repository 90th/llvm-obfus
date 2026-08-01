---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

**Bug summary**
What breaks, and where? Note whether this is a miscompile, wrong output, verifier failure, assertion, or crash.

**LLVM version**
LLVM/Clang version, commit, or package revision used for this reproducer.

**Host compiler**
Compiler and version used to build LLVM-obfus.

**Target triple**
The target triple for the failing case.

**Exact `opt` / `obf-clang` command**
```sh
# Paste the full command line exactly as run.
```

**YAML / `OBF_ENABLE` configuration**
```yaml
# Paste the relevant YAML config and any OBF_ENABLE settings.
```

**Reduced C / LLVM IR input**
```c
// Paste the smallest C or .ll reproducer you have.
```

**Expected result**
What output, IR property, or successful behavior did you expect?

**Actual result / crash**
Paste the wrong output, verifier error, assertion, stack trace, or crash log.

**Relevant target / test information**
List the affected lit test, runtime target, architecture-specific flags, or other target details needed to reproduce.

**Additional context**
Anything else that helps reproduce or narrow the issue.
