#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

int wmain(void) {
  const wchar_t *python = _wgetenv(L"OBF_RUSTC_FAKE_PYTHON");
  const wchar_t *script = _wgetenv(L"OBF_RUSTC_FAKE_SCRIPT");
  if (!python || !script) {
    fputs("fake rustc launcher: missing Python fixture configuration\n", stderr);
    return 2;
  }

  // Preserve the argument tail produced by subprocess.list2cmdline. Rebuilding
  // argv through the CRT spawn functions would lose quoting and empty arguments.
  const wchar_t *tail = GetCommandLineW();
  while (*tail == L' ' || *tail == L'\t')
    ++tail;
  if (*tail == L'"') {
    ++tail;
    while (*tail && *tail != L'"')
      ++tail;
    if (*tail)
      ++tail;
  } else {
    while (*tail && *tail != L' ' && *tail != L'\t')
      ++tail;
  }

  size_t size = wcslen(python) + wcslen(script) + wcslen(tail) + 6;
  wchar_t *command = malloc(size * sizeof(*command));
  if (!command) {
    fputs("fake rustc launcher: cannot allocate command line\n", stderr);
    return 2;
  }
  // Both values are existing file paths, so neither can contain a quote or end
  // in a directory separator on Windows.
  if (swprintf(command, size, L"\"%ls\" \"%ls\"%ls", python, script, tail) < 0) {
    free(command);
    fputs("fake rustc launcher: cannot construct command line\n", stderr);
    return 2;
  }

  STARTUPINFOW startup = {0};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  PROCESS_INFORMATION child = {0};
  BOOL started = CreateProcessW(python, command, NULL, NULL, TRUE, 0, NULL, NULL,
                                &startup, &child);
  free(command);
  if (!started) {
    fprintf(stderr, "fake rustc launcher: CreateProcess failed: %lu\n",
            GetLastError());
    return 2;
  }

  CloseHandle(child.hThread);
  DWORD status = 2;
  BOOL finished = WaitForSingleObject(child.hProcess, INFINITE) == WAIT_OBJECT_0;
  BOOL read_status = finished && GetExitCodeProcess(child.hProcess, &status);
  if (!read_status)
    fprintf(stderr, "fake rustc launcher: cannot read child status: %lu\n",
            GetLastError());
  CloseHandle(child.hProcess);
  return read_status ? (int)status : 2;
}
