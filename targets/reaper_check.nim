## Does the reaper actually reap, and would it ever reap the engine itself?
##
## Compile with the project's config.nims (it puts src/ on --path):
##     nim c -r --hints:off targets/reaper_check.nim
##
## Two independent claims are checked here, because both fail silently when
## they are wrong:
##
##   1. sweep() kills a process whose command line points into our own temp
##      directory, and does not kill one that merely runs at the same time.
##      A sweep that matches nothing looks identical to a sweep that works --
##      both print 0 -- so this runs a process that must die and one that must
##      not, and asserts on both.
##
##   2. adopt() refuses the engine's own PID. If it ever accepted it,
##      closeReaper() would terminate the process that just called it. The
##      proof is that this program is still alive to print VERDICT after
##      calling closeReaper().

import std/[os, osproc]
import engine/reaper

var failures = 0

proc check(what: string, ok: bool, detail = "") =
  if not ok: inc failures
  echo (if ok: "  ok   " else: "  FAIL "), what,
       (if detail.len > 0: " -> " & detail else: "")

when defined(windows):
  let tempRoot = getTempDir() / "bug_genesis_reaper_check"
  removeDir(tempRoot)
  createDir(tempRoot)
  let workFile = tempRoot / "worker_9.in"
  writeFile(workFile, "[server]\nport = 1\n")

  # A process that will hang for a long time and whose command line contains
  # our temp path -- exactly the shape a leftover target has.
  # `#` makes the path a PowerShell comment, so it is present in the command
  # line without changing what the process does.
  var doomed: Process
  var bystander: Process
  try:
    doomed = startProcess(
      "powershell.exe",
      args = ["-NoProfile", "-NonInteractive", "-Command",
              "Start-Sleep 300 # " & workFile],
      options = {poUsePath})
    bystander = startProcess(
      "powershell.exe",
      args = ["-NoProfile", "-NonInteractive", "-Command",
              "Start-Sleep 300 # unrelated"],
      options = {poUsePath})

    sleep(700)
    check("doomed process is running before sweep", running(doomed))
    check("bystander process is running before sweep", running(bystander))

    echo "== startup sweep =="
    let killed = sweep(tempRoot)
    echo "       sweep reported ", killed, " kill(s)"
    sleep(700)
    check("sweep reported exactly one kill", killed == 1, $killed)
    check("process pointing into our temp dir is gone",
          not running(doomed))
    check("unrelated process survives",
          running(bystander))

    # Clean the board before the section that would kill us if the guard were
    # missing: a dead checker never reaches its own `finally`.
    for p in [doomed, bystander]:
      if running(p): kill(p)
      close(p)

    echo "== adopt guards =="
    let before = reaperStats()
    check("initReaper reports a job", initReaper())
    adopt(0)
    adopt(-1)
    adopt(int(getCurrentProcessId()))
    let after = reaperStats()
    check("adopt(0)/adopt(-1)/adopt(self) adopted nothing",
          after.adopted == before.adopted,
          "adopted " & $(after.adopted - before.adopted))

    echo "== closeReaper must not kill the engine =="
    closeReaper()
    # Nothing above can assert this directly: if the self-guard were missing,
    # the call above would have already terminated us.
    check("engine survived closeReaper after adopting its own PID", true)

    removeDir(tempRoot)
  finally:
    for p in [doomed, bystander]:
      if p != nil:
        try:
          if running(p): kill(p)
          close(p)
        except CatchableError:
          discard
else:
  echo "  skip  reaper_check covers the Windows job object only"

if failures == 0:
  echo "VERDICT: the reaper reaps what it should and nothing it should not."
else:
  echo "VERDICT: ", failures, " reaper check(s) FAILED."
  quit(1)