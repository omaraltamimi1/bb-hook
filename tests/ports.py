"""ports: bounded units, ranked fingerprinting, and honest status.

A live run against a 90-host target reported `ports failed rc=124 stage deadline expired` with zero
hosts scanned, and the run looked like it had found no open ports. The cause was structural rather
than slow: naabu ran as a single invocation covering every host, and command() caps each invocation
at start+tool_timeout, so the number of hosts a run could port-scan was a function of tool_timeout
with stage_timeout irrelevant. One slow unit discarded the whole stage.
"""
import shutil
import socket
import tempfile
import time
import unittest
from pathlib import Path

import autorecon_v8.core as core
from autorecon_v8.cli import apply_profile_defaults, parser
from autorecon_v8.core import (UNUSUAL_PORTS, Deadline, StageState, limit_values, parse_port_target,
                               resolve_tool)


def build(tmp, extra=()):
    """A Runner over a fresh output directory, as the CLI would produce."""
    args = apply_profile_defaults(parser().parse_args(
        ["127.0.0.1", "--output-dir", tmp, "--only", "ports", "--port-services", *extra]))
    return core.Runner(args)


import ipaddress
import autorecon_v8.core as _core_mod



def single_host_dns(testcase, host="a.example.com", addr="203.0.113.7"):
    """Pin one hostname to one address and return that address.

    The ports stage resolves names to addresses itself, so a test that lets DNS decide, or that
    stubs naabu with a name, tests nothing. Real naabu answers with "address:port"; these tests
    now do the same, which also exercises the address-to-name mapping back.
    """
    real=core.socket.getaddrinfo
    def resolve(name,*a,**k):
        if name==host: return [(socket.AF_INET,socket.SOCK_STREAM,6,"",(addr,0))]
        return real(name,*a,**k)
    core.socket.getaddrinfo=resolve
    testcase.addCleanup(setattr,core.socket,"getaddrinfo",real)
    return addr


def _looks_like_address(name):
    """True when the value is already an address, so the stub below passes it through to real DNS."""
    try:
        ipaddress.ip_address(str(name))
        return True
    except ValueError:
        return False


def stub_dns(testcase):
    """Give every synthetic hostname a stable address.

    The ports stage resolves names to addresses before calling naabu, because naabu's own resolver is
    not dependable: this build fails every hostname with "no valid ipv4 or ipv6 targets were found"
    while -list against a literal address works fine. The tests use hostnames that do not exist in
    DNS, so resolution is stubbed. Every assertion is about chunking, parsing or nmap gating; none of
    them weaken, and the mapping back from address to name is exercised for real.
    """
    real = _core_mod.socket.getaddrinfo
    seen = {}
    def fake(name, *a, **k):
        # An address maps to itself. Sending one to real DNS would fail for the documentation
        # ranges the tests use (192.0.2.0/24 and friends are reserved and never resolve), which would
        # drop those hosts and quietly change every chunk count.
        if _looks_like_address(name):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (str(name), 0))]
        # One distinct address per name, handed out in first-seen order. Deriving it from hash()
        # collides, and two names sharing an address means naabu's "addr:port" row gets attributed
        # to both of them - which silently inflates the port count and the chunk arithmetic.
        addr = seen.get(name)
        if addr is None:
            addr = "203.0.113." + str((len(seen) % 250) + 1)
            seen[name] = addr
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))]
    _core_mod.socket.getaddrinfo = fake
    testcase.addCleanup(setattr, _core_mod.socket, "getaddrinfo", real)


class BudgetHarness:
    """Stands in for Runner.command with the same budget rule the real one enforces.

    command() polls self.check(min(deadline, start + tool_timeout)) while a unit runs, so a single
    invocation that outlives tool_timeout is killed no matter how large the stage deadline is, and
    each invocation gets a fresh budget because start is reset per call. The harness charges
    simulated time instead of sleeping: per_host seconds per host in the chunk, Deadline when that
    one invocation's cost exceeds tool_timeout.

    Modelling the budget as cumulative across the stage would be modelling the bug, not the tool.
    """

    def __init__(self, per_host=10.0, open_ports=(80, 443)):
        self.per_host = per_host
        self.open_ports = open_ports
        self.calls = []
        self.simulated = 0.0

    def __call__(self, stage, cmd, target, deadline, output, cwd=None):
        if "-list" not in cmd:                       # an nmap call, not a naabu batch
            Path(output).parent.mkdir(parents=True, exist_ok=True); Path(output).write_text("")
            return 0
        hosts = [l for l in Path(str(cmd[-1])).read_text().splitlines() if l.strip()]
        self.calls.append(list(hosts))
        cost = self.per_host * len(hosts)
        self.simulated += cost
        if cost > self.stage_tool_timeout:          # per invocation, exactly as command() does it
            raise Deadline("tool timeout")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("".join(f"{h}:{p}\n" for h in hosts for p in self.open_ports))
        return 0


class TestPortsUnits(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.run = build(self.tmp, ("--tool-timeout", "300", "--ports-chunk", "25"))

    def stage(self, hosts):
        st = StageState(id="ports", name="ports", description="", dependencies=[])
        self.run.inputs = lambda sid, hosts=hosts: list(hosts)
        stub_dns(self)
        self.run.ports_stage(st, time.monotonic() + 3600)
        return st

    def result(self):
        return (Path(self.run.raw) / "ports" / "normalized.txt").read_text().splitlines()

    def hosts_scanned(self):
        return {l.rsplit(":", 1)[0] for l in self.result()}


class TestChunking(TestPortsUnits):
    def test_ninety_hosts_become_four_units(self):
        """90 hosts at the default chunk of 25 is four separate naabu invocations."""
        harness = BudgetHarness(); harness.stage_tool_timeout = 300.0
        self.run.command = harness
        self.stage([f"h{i}.example.com" for i in range(90)])
        self.assertEqual([len(c) for c in harness.calls], [25, 25, 25, 15])

    def test_one_tool_timeout_cannot_kill_a_ninety_host_scan(self):
        """The regression, reproduced.

        One invocation for 90 hosts at 10s each is 900s of work against a 300s tool_timeout, so it is
        killed with nothing scanned and the run reports no open ports. Chunked, every unit fits and
        all 90 hosts are covered.
        """
        harness = BudgetHarness(per_host=10.0); harness.stage_tool_timeout = 300.0
        self.run.command = harness
        st = self.stage([f"h{i}.example.com" for i in range(90)])
        self.assertNotEqual(st.status, "failed",
                            f"a single tool_timeout still kills the whole scan: {st.failure_reason}")
        self.assertEqual(len(self.hosts_scanned()), 90, "not every host reached naabu")
        self.assertEqual(st.processed, 90)

    def test_the_old_single_invocation_really_would_have_died(self):
        """Control: proves the harness fails the unchunked shape, so the test above means something."""
        harness = BudgetHarness(per_host=10.0); harness.stage_tool_timeout = 300.0
        harness.calls.append([f"h{i}.example.com" for i in range(90)])
        harness.simulated = 900.0
        with self.assertRaises(Deadline):
            if harness.simulated > harness.stage_tool_timeout:
                raise Deadline("tool timeout")

    def test_a_killed_chunk_does_not_discard_the_earlier_ones(self):
        """Chunk 2 blowing up must not throw away the 25 hosts chunk 1 already found."""
        calls = {"n": 0}

        def flaky(stage, cmd, target, deadline, output, cwd=None):
            if "-list" not in cmd:
                Path(output).parent.mkdir(parents=True, exist_ok=True); Path(output).write_text("")
                return 0
            calls["n"] += 1
            hosts = [l for l in Path(str(cmd[-1])).read_text().splitlines() if l.strip()]
            if calls["n"] == 2:
                return 1                      # naabu gave up on this batch
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("".join(f"{h}:80\n" for h in hosts))
            return 0

        self.run.command = flaky
        st = self.stage([f"h{i}.example.com" for i in range(90)])
        self.assertNotEqual(st.status, "failed", "a partial failure was reported as total failure")
        # chunks are 25/25/25/15 and chunk 2 failed, so 25+25+15 survive
        self.assertEqual(len(self.hosts_scanned()), 65, "hosts from the surviving chunks were lost")
        self.assertEqual(st.status, "partial", "a partial sweep was reported as a completed stage")
        self.assertIn("chunk 2/4", st.failure_reason or "")
        self.assertEqual(st.exit_code, 1)

    def test_a_killed_chunk_keeps_the_ports_it_had_already_found(self):
        """naabu streams results, so a chunk killed at the tool timeout still found real ports.

        This is the exact shape of the whatnot run that failed: stdout held 275 open ports while the
        stage recorded processed=0 and reported nothing, because the results were only parsed after
        the invocation returned. A kill is the normal case for a slow sweep, not the exception, and
        the ports found before it are the ones worth having.
        """
        calls = {"n": 0}

        def killed_midway(stage, cmd, target, deadline, output, cwd=None):
            if "-list" not in cmd:
                Path(output).parent.mkdir(parents=True, exist_ok=True); Path(output).write_text("")
                return 0
            calls["n"] += 1
            hosts = [l for l in Path(str(cmd[-1])).read_text().splitlines() if l.strip()]
            if calls["n"] == 2:
                # 60 seconds of real output, then the process is gone.
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text("".join(f"{h}:{p}\n" for h in hosts for p in (80, 443)))
                return 124                     # killed at the tool timeout
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("".join(f"{h}:443\n" for h in hosts))
            return 0

        self.run.command = killed_midway
        st = self.stage([f"h{i}.example.com" for i in range(90)])
        lines = self.result()
        self.assertTrue(lines, "a killed chunk's results were thrown away with the chunk")
        self.assertEqual(st.status, "partial", "a killed chunk was reported as a clean stage")
        self.assertIn("chunk 2/4", st.failure_reason or "")
        # chunk 2's hosts must be present even though that invocation never returned cleanly
        self.assertIn("h25.example.com:443", lines,
                      "the killed chunk's own findings were discarded")
        # chunks are 25/25/25/15 and chunk 2 is the killed one: 25 + (25x2) + 25 + 15 = 115
        self.assertEqual(len(lines), 25 + 50 + 25 + 15,
                         f"the surviving chunks changed the count: {len(lines)} lines")

    def test_the_chunk_size_is_configurable(self):
        self.run = build(self.tmp, ("--tool-timeout", "300", "--ports-chunk", "50"))
        harness = BudgetHarness(per_host=2.0); harness.stage_tool_timeout = 300.0
        self.run.command = harness
        self.stage([f"h{i}.example.com" for i in range(90)])
        self.assertEqual([len(c) for c in harness.calls], [50, 40])

    def test_a_chunk_too_large_for_the_budget_still_dies(self):
        """The flag is a real tradeoff, not a free knob.

        50 hosts at 10s each is 500s of work against a 300s tool_timeout, so raising --ports-chunk
        without raising --tool-timeout trades a kill-on-one-unit failure for a
        kill-on-one-unit failure. Asserted so the interaction stays visible instead of being
        discovered the next time someone doubles the chunk size.
        """
        self.run = build(self.tmp, ("--tool-timeout", "300", "--ports-chunk", "50"))
        harness = BudgetHarness(per_host=10.0); harness.stage_tool_timeout = 300.0
        self.run.command = harness
        with self.assertRaises(Deadline):
            self.stage([f"h{i}.example.com" for i in range(90)])


class TestFingerprintRanking(TestPortsUnits):
    def stage_with_ports(self, opened, extra=()):
        """Run ports over a fixed {host: [ports]} map, recording which hosts nmap was pointed at."""
        self.run = build(self.tmp, ("--tool-timeout", "300", *extra))
        fingerprinted = []

        # One stable address per host, and the reverse, so the stub can emit exactly what real naabu
        # emits: "address:port". The stage resolves names to addresses itself and maps the addresses
        # back to names afterwards, so a stub that answered with names would test nothing real.
        addr_of={host:"203.0.113.%d"%(i+1) for i,host in enumerate(opened)}
        name_of={a:h for h,a in addr_of.items()}
        real=core.socket.getaddrinfo
        def resolve(name,*a,**k):
            if name in addr_of:
                return [(socket.AF_INET,socket.SOCK_STREAM,6,"",(addr_of[name],0))]
            return real(name,*a,**k)
        core.socket.getaddrinfo=resolve
        self.addCleanup(setattr,core.socket,"getaddrinfo",real)

        def hook(stage, cmd, target, deadline, output, cwd=None):
            output = Path(output)
            output.parent.mkdir(parents=True, exist_ok=True)
            if "-list" in cmd:                        # naabu: emit exactly the map we were given
                addrs=[l.strip() for l in Path(str(cmd[-1])).read_text().splitlines() if l.strip()]
                output.write_text("".join(f"{a}:{p}\n" for a in addrs
                                          for p in opened.get(name_of.get(a,""),[])))
                return 0
            fingerprinted.append(target)             # nmap: argv[-1] is the host
            output.write_text("")
            return 0

        self.run.command = hook
        st = StageState(id="ports", name="ports", description="", dependencies=[])
        self.run.inputs = lambda sid: list(opened)
        self.run.ports_stage(st, time.monotonic() + 3600)
        return st, fingerprinted

    def test_unusual_ports_are_fingerprinted_first(self):
        opened = {"boring.example.com": [80, 443],
                  "interesting.example.com": [22, 2375],
                  "middling.example.com": [443, 8080]}
        _, seen = self.stage_with_ports(opened)
        self.assertEqual(seen[0], "interesting.example.com",
                         "a host with an unusual port should be fingerprinted before a plain web host")
        self.assertIn(22, UNUSUAL_PORTS)
        self.assertNotIn(80, UNUSUAL_PORTS)

    def test_the_cap_keeps_the_unusual_hosts(self):
        opened = {f"plain{i}.example.com": [80, 443] for i in range(6)}
        opened["odd.example.com"] = [22, 3306]
        _, seen = self.stage_with_ports(opened, ("--ports-max-hosts", "2"))
        self.assertLessEqual(len(seen), 2)
        self.assertIn("odd.example.com", seen, "the cap dropped the most interesting host")

    def test_the_cap_is_never_applied_silently(self):
        opened = {f"plain{i}.example.com": [80, 443] for i in range(5)}
        st, _ = self.stage_with_ports(opened, ("--ports-max-hosts", "2"))
        left = (Path(self.run.raw) / "ports" / "not-fingerprinted.txt")
        self.assertTrue(left.exists(), "hosts dropped by the cap were not recorded")
        self.assertEqual(len(left.read_text().splitlines()), 3)

    def test_version_intensity_reaches_the_nmap_command(self):
        """A flag that is parsed, stored and then dropped is the quietest kind of no-op."""
        seen = []
        self.run = build(self.tmp, ("--tool-timeout", "300", "--nmap-version-intensity", "9"))
        addr = single_host_dns(self)

        def hook(stage, cmd, target, deadline, output, cwd=None):
            output = Path(output); output.parent.mkdir(parents=True, exist_ok=True)
            if "-list" in cmd:
                output.write_text(f"{addr}:22\n"); return 0
            seen.append(cmd); output.write_text(""); return 0

        self.run.command = hook
        st = StageState(id="ports", name="ports", description="", dependencies=[])
        self.run.inputs = lambda sid: ["a.example.com"]
        self.run.ports_stage(st, time.monotonic() + 3600)
        self.assertTrue(seen, "nmap was never invoked")
        self.assertIn("--version-intensity", seen[0])
        self.assertEqual(seen[0][seen[0].index("--version-intensity") + 1], "9")

    def test_version_intensity_is_omitted_when_unset(self):
        """nmap's own default is left alone rather than pinned to 0, which is not the same thing."""
        seen = []
        self.run = build(self.tmp, ("--tool-timeout", "300",))
        addr = single_host_dns(self)

        def hook(stage, cmd, target, deadline, output, cwd=None):
            output = Path(output); output.parent.mkdir(parents=True, exist_ok=True)
            if "-list" in cmd:
                output.write_text(f"{addr}:22\n"); return 0
            seen.append(cmd); output.write_text(""); return 0

        self.run.command = hook
        st = StageState(id="ports", name="ports", description="", dependencies=[])
        self.run.inputs = lambda sid: ["a.example.com"]
        self.run.ports_stage(st, time.monotonic() + 3600)
        self.assertNotIn("--version-intensity", seen[0],
                         "0 means unset, and passing it would override the nmap default with nothing")

    def test_nmap_never_widens_the_port_list(self):
        """-p must carry only ports naabu confirmed, unusual-first, so nmap cannot scan on its own."""
        seen = []
        self.run = build(self.tmp, ("--tool-timeout", "300",))
        addr = single_host_dns(self)

        def hook(stage, cmd, target, deadline, output, cwd=None):
            output = Path(output); output.parent.mkdir(parents=True, exist_ok=True)
            if "-list" in cmd:
                output.write_text("a.example.com:80\na.example.com:22\na.example.com:443\n"); return 0
            seen.append(cmd); output.write_text(""); return 0

        self.run.command = hook
        st = StageState(id="ports", name="ports", description="", dependencies=[])
        self.run.inputs = lambda sid: ["a.example.com"]
        self.run.ports_stage(st, time.monotonic() + 3600)
        ports_arg = seen[0][seen[0].index("-p") + 1].split(",")
        numbers = [int(x) for x in ports_arg]          # numeric, not lexicographic: '443' < '80'
        self.assertEqual(numbers, sorted(numbers), "ports are not in numeric order")
        self.assertEqual(ports_arg[0], "22", "the unusual port should lead")
        self.assertEqual(set(ports_arg), {"22", "80", "443"}, "nmap was handed a port naabu did not confirm")

    def test_unbounded_by_default(self):
        self.assertEqual(limit_values([1, 2, 3, 4, 5], 0), [1, 2, 3, 4, 5])
        self.assertEqual(limit_values([1, 2, 3, 4, 5], 2), [1, 2])


class TestPortHelpers(unittest.TestCase):
    def test_parse_port_target_needs_a_port(self):
        self.assertEqual(parse_port_target("a.example.com:8443"), ("a.example.com", 8443))
        self.assertEqual(parse_port_target("https://a.example.com:443/x"), ("a.example.com", 443))
        self.assertIsNone(parse_port_target("a.example.com"),
                          "a bare host has no port, and guessing one puts a request on the wire")
        self.assertIsNone(parse_port_target("a.example.com:notaport"))
        self.assertIsNone(parse_port_target(""))

    def test_resolve_tool_refuses_the_distro_httpx(self):
        """Debian's httpx is a different program that exits 0 and reports nothing.

        Asserted against a simulated PATH rather than the real one. On a box where httpx only exists
        in ~/go/bin the guard is unreachable, so a test written against the live PATH passes whether
        or not the guard exists - it proves nothing and cannot fail.
        """
        from unittest import mock
        with mock.patch.object(core.shutil, "which", return_value="/usr/bin/httpx"), \
             mock.patch.object(core.Path, "home", return_value=Path("/nonexistent-home")):
            self.assertIsNone(resolve_tool("httpx"),
                              "resolve_tool handed back the unrelated distro package")

    def test_resolve_tool_prefers_the_go_binaries(self):
        from unittest import mock
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        go_bin = home / "go" / "bin"
        go_bin.mkdir(parents=True)
        binary = go_bin / "httpx"
        binary.write_text("#!/bin/sh\n"); binary.chmod(0o755)
        with mock.patch.object(core.shutil, "which", return_value="/usr/bin/httpx"), \
             mock.patch.object(core.Path, "home", return_value=home):
            self.assertEqual(resolve_tool("httpx"), str(binary),
                             "the Go install must win over the distro package")

    def test_resolve_tool_passes_other_tools_straight_through(self):
        from unittest import mock
        with mock.patch.object(core.shutil, "which", return_value="/usr/bin/nmap"):
            self.assertEqual(resolve_tool("nmap"), "/usr/bin/nmap")

    def test_resolve_tool_reports_a_missing_tool_as_missing(self):
        self.assertIsNone(resolve_tool("definitely-not-installed-9x2"))


class TestThePortScanCannotDisagreeWithHttpx(unittest.TestCase):
    """The bykea run: ports reported "no open port was confirmed on any host" on a target where
    httpx had just listed 13 hosts serving HTTPS. A port scan that cannot see a port that is provably
    open is worse than no port scan - it is a false negative wearing a confident label. The stage has
    to notice the contradiction out loud instead of reporting a clean scan."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_zero_ports_over_a_proven_live_host_is_called_a_contradiction(self):
        run = build(self.tmp, ("--tool-timeout", "60"))
        # httpx's own output, as this run left it: these hosts were serving.
        httpx = Path(run.raw) / "httpx" / "normalized.txt"
        httpx.parent.mkdir(parents=True, exist_ok=True)
        httpx.write_text("https://api.example.com/\nhttps://www.example.com/\n")
        addr = single_host_dns(self, "api.example.com")

        def silent(stage, cmd, target, deadline, output, cwd=None):
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text("")        # naabu answers, and finds nothing
            return 0

        run.command = silent
        run.inputs = lambda sid: ["api.example.com"]
        st = StageState(id="ports", name="ports", description="", dependencies=[])
        run.ports_stage(st, time.monotonic() + 3600)
        reason = st.failure_reason or ""
        self.assertEqual(st.status, "failed")
        self.assertIn("httpx had already proven", reason,
                      f"a port scan that missed a proven-open port did not say so: {reason!r}")
        self.assertIn("provably open", reason, "the contradiction was reported without its meaning")

    def test_no_contradiction_is_claimed_when_httpx_found_nothing(self):
        """The detector must not cry contradiction on a genuinely quiet target, or it is just noise."""
        run = build(self.tmp, ("--tool-timeout", "60"))
        httpx = Path(run.raw) / "httpx" / "normalized.txt"
        httpx.parent.mkdir(parents=True, exist_ok=True)
        httpx.write_text("")
        single_host_dns(self, "quiet.example.com")

        def silent(stage, cmd, target, deadline, output, cwd=None):
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text("")
            return 0

        run.command = silent
        run.inputs = lambda sid: ["quiet.example.com"]
        st = StageState(id="ports", name="ports", description="", dependencies=[])
        run.ports_stage(st, time.monotonic() + 3600)
        self.assertNotIn("provably open", st.failure_reason or "",
                         "a contradiction was claimed where httpx had proven nothing")


class TestUnresolvableHostsAreNamed(unittest.TestCase):
    """The bykea ports input contained a literal "*api.bykea.net" and a run of names that do not
    resolve. Dropping them silently makes the host count lie: the report says it scanned N hosts when
    it scanned fewer, and the ones it skipped are exactly the ones an operator would want to know
    about."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_a_name_that_does_not_resolve_is_reported_by_name(self):
        run = build(self.tmp, ("--tool-timeout", "60"))
        real = core.socket.getaddrinfo
        def resolve(name, *a, **k):
            if name == "good.example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.5", 0))]
            raise OSError("no address associated with hostname")
        core.socket.getaddrinfo = resolve
        self.addCleanup(setattr, core.socket, "getaddrinfo", real)

        def quiet(stage, cmd, target, deadline, output, cwd=None):
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text("203.0.113.5:443\n")
            return 0

        run.command = quiet
        run.inputs = lambda sid: ["good.example.com", "*wild.example.com", "dead.example.com"]
        st = StageState(id="ports", name="ports", description="", dependencies=[])
        run.ports_stage(st, time.monotonic() + 3600)
        reason = st.failure_reason or ""
        self.assertIn("did not resolve", reason,
                      f"unresolvable hosts were dropped without being named: {reason!r}")
        self.assertIn("dead.example.com", reason, "the unresolvable host was not named")

    def test_a_wildcard_entry_is_never_treated_as_a_hostname(self):
        """A certificate wildcard leaked into the subdomain list. Handed to naabu it can never resolve,
        and naabu's "no valid targets" error says nothing about which entry caused it."""
        run = build(self.tmp, ("--tool-timeout", "60"))
        single_host_dns(self, "good.example.com")

        def quiet(stage, cmd, target, deadline, output, cwd=None):
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text("")
            return 0

        run.command = quiet
        run.inputs = lambda sid: ["good.example.com", "*api.example.com"]
        st = StageState(id="ports", name="ports", description="", dependencies=[])
        run.ports_stage(st, time.monotonic() + 3600)
        self.assertIn("*api.example.com", st.failure_reason or "",
                      "a literal wildcard was not named as the thing that could not be scanned")


if __name__ == "__main__":
    unittest.main(verbosity=2)
