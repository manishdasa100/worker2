"""
Which syscalls each language's compile and run phases actually make, so the seccomp
allowlists in sandbox/*.kafel rest on evidence. Re-run after any base-image, glibc,
toolchain or gVisor upgrade, and review what it lists as unnamed:

    .venv/bin/python tools/profile_syscalls.py

Builds a throwaway image (the executor image plus strace), then straces each language
handler's own compile and run commands on a sample program, under runsc, with no jail
and no seccomp. Prints per-language, per-phase syscall sets, each phase's union, and
the syscalls that phase's policy doesn't name (so they get ENOSYS). Needs Docker.
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE = os.environ.get("EXECUTOR_IMAGE", "codinglemons-executor")
RUNTIME = os.environ.get("PROFILE_RUNTIME", "runsc")
PROFILE_IMAGE = "codinglemons-syscall-profile"

# Sample programs (after judgebox's tools/profile-syscalls.sh): stdin parsing, a
# container-heavy solution, exceptions, threads, deep recursion and a large allocation.
INPUT = "5 9\n2 7 11 15 1\n"
PROGRAMS = {
    "python": (
        "class Solution:\n"
        "    def twoSum(self, nums, target):\n"
        "        seen = {}\n"
        "        for i, x in enumerate(nums):\n"
        "            if target - x in seen: return [seen[target - x], i]\n"
        "            seen[x] = i\n"
        "        return []\n",
        "import sys, heapq, json, re, functools, threading\n"
        "from collections import Counter\nfrom solution import Solution\n"
        "sys.setrecursionlimit(10**6)\n"
        "@functools.lru_cache(None)\ndef fib(n): return n if n < 2 else fib(n-1) + fib(n-2)\n"
        "data = sys.stdin.read().split(); n, t = int(data[0]), int(data[1])\n"
        "r = Solution().twoSum(list(map(int, data[2:2+n])), t)\n"
        "th = threading.Thread(target=lambda: None); th.start(); th.join()\n"
        "try:\n    raise ValueError('x')\nexcept ValueError:\n    pass\n"
        "big = [0] * 5_000_000\n"
        "print(r, fib(300) % 1000, json.dumps(Counter('hello')), len(big), re.sub(r'\\d', '#', 'a1'))\n",
    ),
    "cpp": (
        "#include <unordered_map>\n#include <vector>\n"
        "std::vector<int> twoSum(std::vector<int>& nums, int target) {\n"
        "  std::unordered_map<int,int> seen;\n"
        "  for (int i = 0; i < (int)nums.size(); i++) { auto it = seen.find(target - nums[i]);\n"
        "    if (it != seen.end()) return {it->second, i}; seen[nums[i]] = i; }\n"
        "  return {}; }\n",
        "#include <bits/stdc++.h>\n#include \"solution.cpp\"\nusing namespace std;\n"
        "int depth(int n) { return n == 0 ? 0 : 1 + depth(n - 1); }\n"
        "int main() { ios::sync_with_stdio(false); cin.tie(nullptr);\n"
        "  int n, t; cin >> n >> t; vector<int> v(n); for (auto &x : v) cin >> x;\n"
        "  auto r = twoSum(v, t);\n"
        "  try { throw runtime_error(\"x\"); } catch (const exception &) {}\n"
        "  vector<thread> th; atomic<long> acc{0};\n"
        "  for (int i = 0; i < 2; i++) th.emplace_back([&]{ for (int j = 0; j < 100000; j++) acc++; });\n"
        "  for (auto &x : th) x.join();\n"
        "  vector<long long> big(8'000'000, 7);\n"
        "  cout << r[0] << ' ' << r[1] << ' ' << depth(100000) << ' ' << acc << ' ' << big[42] << '\\n'; }\n",
    ),
    "java": (
        "import java.util.*;\n"
        "class Solution { static int[] twoSum(int[] nums, int target) { Map<Integer,Integer> s = new HashMap<>();\n"
        "  for (int i = 0; i < nums.length; i++) { Integer j = s.get(target - nums[i]);\n"
        "    if (j != null) return new int[]{j, i}; s.put(nums[i], i); } return new int[0]; } }\n",
        "import java.io.*;\nimport java.util.*;\nimport java.util.stream.*;\n"
        "public class Main { static int depth(int n) { return n == 0 ? 0 : 1 + depth(n - 1); }\n"
        "  public static void main(String[] args) throws Exception {\n"
        "    BufferedReader br = new BufferedReader(new InputStreamReader(System.in));\n"
        "    StringTokenizer st = new StringTokenizer(br.readLine());\n"
        "    int n = Integer.parseInt(st.nextToken()), t = Integer.parseInt(st.nextToken());\n"
        "    st = new StringTokenizer(br.readLine()); int[] a = new int[n];\n"
        "    for (int i = 0; i < n; i++) a[i] = Integer.parseInt(st.nextToken());\n"
        "    int[] r = Solution.twoSum(a, t);\n"
        "    List<Integer> l = IntStream.range(0, 100000).boxed().sorted(Comparator.reverseOrder())"
        ".collect(Collectors.toList());\n"
        "    try { Object o = null; o.toString(); } catch (NullPointerException e) { }\n"
        "    Thread th = new Thread(() -> {}); th.start(); th.join();\n"
        "    long[] big = new long[8_000_000]; Arrays.fill(big, 3);\n"
        "    System.out.println(r[0] + \" \" + r[1] + \" \" + l.get(0) + \" \" + depth(5000) + \" \" + big[9]"
        " + \" \" + String.format(\"%.2f\", Math.sqrt(2))); } }\n",
    ),
}

# strace prints the userspace names; kafel uses the kernel's for these.
KAFEL_NAMES = {"stat": "newstat", "fstat": "newfstat", "lstat": "newlstat", "uname": "newuname",
               "sendfile": "sendfile64", "umount2": "umount"}
CODE_DIR = "/code"


def traced(name, argv, stdin):
    """Run argv under strace -f in CODE_DIR; the set of syscalls it made."""
    with tempfile.NamedTemporaryFile(suffix=".trace") as trace:
        result = subprocess.run(["strace", "-f", "-qq", "-e", "signal=none", "-o", trace.name, *argv],
                                cwd=CODE_DIR, input=stdin, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"!! {name} exited {result.returncode}: {result.stderr.strip()[-500:]}", file=sys.stderr)
        # Lines look like "1234  openat(AT_FDCWD, ..." or "1234  <... read resumed>".
        names = re.findall(r"^\d+ +([a-z0-9_]+)\(", open(trace.name).read(), re.M)
    return {KAFEL_NAMES.get(n, n) for n in names}


def profile():
    """Inside the profile container: print the report."""
    sys.path.insert(0, "/opt/executor")
    from languages import LANGUAGES
    sets = {}
    for lang_name, lang in LANGUAGES.items():
        os.makedirs(CODE_DIR, exist_ok=True)
        subprocess.run(f"rm -rf {CODE_DIR}/*", shell=True, check=True)
        user_code, driver_code = PROGRAMS[lang_name]
        lang.write_files(CODE_DIR, user_code, driver_code)
        if compile_command := lang.compile_command():
            sets[(lang_name, "compile")] = traced(f"{lang_name} compile", compile_command, "")
        sets[(lang_name, "run")] = traced(f"{lang_name} run", lang.run_command(256), INPUT)

    print("### Per-language, per-phase syscall sets")
    for (lang_name, phase), names in sets.items():
        print(f"{lang_name + '.' + phase:16} {len(names):3}  {' '.join(sorted(names))}")
    print(f"\n### Union of all phases\n{' '.join(sorted(set().union(*sets.values())))}")
    for phase in ("run", "compile"):
        union = set().union(*(s for (_, p), s in sets.items() if p == phase))
        policy = re.sub(r"//.*", "", open(f"/opt/executor/sandbox/{phase}.kafel").read())
        named = set(re.findall(r"\b[a-z0-9_]+\b", policy))
        print(f"\n### Union of {phase} phases ({len(union)})\n{' '.join(sorted(union))}")
        print(f"\n### In the {phase} union but not named in sandbox/{phase}.kafel (they get ENOSYS)\n"
              f"{' '.join(sorted(union - named)) or '(none)'}")


def main():
    """On the host: build the profile image and run profile() inside it."""
    dockerfile = f"FROM {IMAGE}\nRUN apt-get update && apt-get install -y --no-install-recommends strace\n"
    subprocess.run(["docker", "build", "-q", "--network=host", "-t", IMAGE, ROOT],
                   check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["docker", "build", "-q", "--network=host", "-t", PROFILE_IMAGE, "-"],
                   input=dockerfile, text=True, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["docker", "run", "--rm", f"--runtime={RUNTIME}", "--network=none",
                    "-v", f"{os.path.abspath(__file__)}:/profile_syscalls.py:ro",
                    PROFILE_IMAGE, "python3", "/profile_syscalls.py", "--inside"], check=True)


if __name__ == "__main__":
    profile() if sys.argv[1:] == ["--inside"] else main()
