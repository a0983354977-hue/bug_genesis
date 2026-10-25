## reaper — make a target die when the engine does.
##
## Phase 4.2. Measured, not assumed: with 4 workers running a target that has a
## genuine infinite loop (targets/cfgparser.py's continuation path), killing the
## engine's PID alone left **1 python.exe running indefinitely** — baseline was
## 0, four were alive during the run, and one survived the engine by minutes.
## It would never have exited on its own.
##
## The cause is structural. On Windows a child is *not* killed when its parent
## dies, and the engine's own reap path (`executor.runOnce`, kill +
## `waitForExit(KillGraceMs)`) simply never runs again once the engine is gone.
## A bridge survives this because `serve()` reads `for line in stdin` and exits
## when the pipe closes; a **hung target has no such tripwire** — it is inside a
## `subprocess`/`waitForExit` wait that no longer has anyone waiting on it.
##
## The fix is the operating-system mechanism built for exactly this: a Job
## Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Every child is assigned to
## the job; when the engine's handle closes — cleanly, by crash, or by
## `taskkill /F` — Windows terminates everything assigned to it, immediately and
## without a restart. A PID list on disk could only reap at *next* launch, which
## leaves the window open precisely when it matters.
##
## Failure is non-fatal by design: if the job cannot be created or a process
## cannot be assigned (nested-job policy, permissions), the campaign continues
## with the previous behaviour and reports it once. Losing a reaper must not
## cost a campaign its observations.
##
## POSIX is not covered here: `setpgid`/`prctl(PR_SET_PDEATHSIG)` would be the
## equivalent and are a separate, testable piece of work. This module refuses to
## pretend otherwise — `sweep` is the only cross-platform path.

import std/strutils

when defined(windows):
  # `streams` for Stream.readAll -- without it, readAll resolves to the
  # File overload and the type error points at the wrong thing entirely.
  import std/[os, osproc, streams, winlean]

  const
    PROCESS_SET_QUOTA = 0x0100'u32
    PROCESS_TERMINATE = 0x0001'u32
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000'u32
    JobObjectExtendedLimitInformation = 9'i32
    SYNCHRONIZE = 0x00100000'u32

  # Layouts are written out field by field with explicit padding: these are
  # passed to the Windows ABI, where a compiler-inserted difference of 4 bytes
  # would silently corrupt the limit flags rather than raise anything.
  type
    IoCounters = object
      readOperationCount: uint64
      writeOperationCount: uint64
      otherOperationCount: uint64
      readTransferCount: uint64
      writeTransferCount: uint64
      otherTransferCount: uint64

    JobBasicLimitInformation = object
      perProcessUserTimeLimit: int64
      perJobUserTimeLimit: int64
      limitFlags: uint32
      pad0: uint32
      minimumWorkingSetSize: uint
      maximumWorkingSetSize: uint
      activeProcessLimit: uint32
      pad1: uint32
      affinity: uint
      priorityClass: uint32
      schedulingClass: uint32

    JobExtendedLimitInformation = object
      basicLimitInformation: JobBasicLimitInformation
      ioInfo: IoCounters
      processMemoryLimit: uint
      jobMemoryLimit: uint
      peakProcessMemoryUsed: uint
      peakJobMemoryUsed: uint

  proc createJobObject(lpJobAttributes: pointer, lpName: cstring): Handle
    {.stdcall, dynlib: "kernel32", importc: "CreateJobObjectW".}
  proc setInformationJobObject(hJob: Handle, infoClass: int32,
                               lpJobObjectInfo: pointer,
                               cbJobObjectInfoLength: uint32): int32
    {.stdcall, dynlib: "kernel32", importc: "SetInformationJobObject".}
  proc assignProcessToJobObject(hJob: Handle, hProcess: Handle): int32
    {.stdcall, dynlib: "kernel32", importc: "AssignProcessToJobObject".}
  proc openProcess(dwDesiredAccess: uint32, bInheritHandle: int32,
                   dwProcessId: uint32): Handle
    {.stdcall, dynlib: "kernel32", importc: "OpenProcess".}
  proc closeHandle(hObject: Handle): int32
    {.stdcall, dynlib: "kernel32", importc: "CloseHandle".}
  proc getLastError(): uint32
    {.stdcall, dynlib: "kernel32", importc: "GetLastError".}

  var
    jobHandle: Handle
    jobFailed = false
    jobAdopted = 0
    jobRejected = 0

  proc initReaper*(): bool =
    ## Create the job once, at campaign start. Returns false when unavailable,
    ## in which case nothing else in this module will run.
    if jobHandle != 0: return true
    if jobFailed: return false

    jobHandle = createJobObject(nil, nil)
    if jobHandle == 0:
      jobFailed = true
      return false

    var info = JobExtendedLimitInformation()
    info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if setInformationJobObject(jobHandle, JobObjectExtendedLimitInformation,
                               addr info, uint32(sizeof(info))) == 0:
      discard closeHandle(jobHandle)
      jobHandle = 0
      jobFailed = true
      return false
    true

  proc adopt*(pid: int) =
    ## Put one child under the job's umbrella. Cheap enough for the hot path:
    ## OpenProcess + Assign + Close, three syscalls per execution.
    ##
    ## The self-check is not paranoia: adopting our own PID would make
    ## `closeReaper()` at campaign end terminate the engine that just called it.
    if jobHandle == 0 or pid <= 0 or pid == int(getCurrentProcessId()): return
    let h = openProcess(PROCESS_SET_QUOTA or PROCESS_TERMINATE or SYNCHRONIZE,
                        0, uint32(pid))
    if h == 0:
      inc jobRejected
      return
    if assignProcessToJobObject(jobHandle, h) == 0:
      inc jobRejected
    else:
      inc jobAdopted
    discard closeHandle(h)

  proc closeReaper*() =
    ## Clean exit only. Closing the handle releases any child still running —
    ## which is the desired behaviour: nothing the campaign started outlives it.
    if jobHandle != 0:
      discard closeHandle(jobHandle)
      jobHandle = 0

  proc reaperStats*(): tuple[adopted, rejected: int] =
    (jobAdopted, jobRejected)

else:
  # Non-Windows: no job object, so no immediate reaping. sweep() still applies.
  proc initReaper*(): bool = false
  proc adopt*(pid: int) = discard
  proc closeReaper*() = discard
  proc reaperStats*(): tuple[adopted, rejected: int] = (0, 0)

# ---------------------------------------------------------------------------
# Startup sweep
# ---------------------------------------------------------------------------

proc sweep*(tempRoot: string): int =
  ## Kill anything a *previous* engine instance left behind.
  ##
  ## Two users: (1) orphans from before this feature existed, and (2) a
  ## belt-and-braces pass for the case where the job itself failed to
  ## initialise. Matched on our own temp directory, so the sweep cannot touch a
  ## process that merely happens to share an image name — the earlier kill test
  ## had to enumerate PIDs by hand for exactly that reason.
  ##
  ## Returns the number of processes terminated, 0 when none.
  result = 0
  when defined(windows):
    if not dirExists(tempRoot): return 0
    # Keep the backslashes. A Windows command line uses them, and `-like` does
    # not treat `\` as a wildcard -- normalising to `/` would silently match
    # nothing while still returning a well-formed 0.
    let needle = tempRoot.replace("'", "''")
    let script = (
      "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and " &
      "$_.CommandLine -like '*" & needle & "*' -and " &
      "$_.ProcessId -ne $PID } | ForEach-Object { " &
      "Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; " &
      "'x' } | Measure-Object | Select-Object -ExpandProperty Count"
    )
    var p: Process
    try:
      p = startProcess("powershell.exe",
                       args = ["-NoProfile", "-NonInteractive", "-Command", script],
                       options = {poUsePath, poStdErrToStdOut})
    except CatchableError:
      return 0
    try:
      discard waitForExit(p, 15_000)
      # `out` is a Nim keyword -- a lesson re-learned here.
      let text = p.outputStream.readAll().strip()
      if text.len > 0:
        try: result = parseInt(text)
        except ValueError: result = 0
    except CatchableError:
      result = 0
    finally:
      try:
        if running(p): kill(p)
        close(p)
      except CatchableError:
        discard