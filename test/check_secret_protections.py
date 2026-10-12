#!/usr/bin/env python3
"""Static check of the secret protections in role task files.

Usage: check_secret_protections.py FILE.yml [FILE.yml ...]
Exit 0 when every file is clean, 1 when a rule is broken (one line per
finding, "file: task name: [rule] explanation"), 2 on a file that cannot be
read. Run by test/secret_protections.sh, which is part of `make test`.

A task "references a secret" when the name of one of SECRET_NAMES appears
anywhere in its arguments, at any depth (strings, lists, dicts, nested
blocks). The task keywords listed in META_KEYS are not arguments: a name in
`when` or `changed_when` is evaluated but never printed, so it does not count.

Rules:
  [no_log]            a task that references a secret has the literal
                      `no_log: true`. Exception: the `that:` of an assert,
                      which ansible does not evaluate into output (see the
                      message rule below).
  [diff]              a copy, template, yum_repository or other file-writing
                      module that references a secret also has the literal
                      `diff: false`, because --diff prints file content even
                      where no_log would hide the result.
  [forbidden-module]  command, shell, script, raw, expect, debug, fail, uri,
                      get_url and pause never reference a secret: they put it
                      on a command line, in a process list or in a message.
  [secret-in-message] an assert may test a secret (`that:`), for instance for
                      emptiness. Its fail_msg, success_msg and msg must not
                      interpolate one: a name inside `{{ }}` or `{% %}`
                      there is flagged. A plain mention of the variable's name
                      in prose is not an interpolation and passes.
"""
import re
import sys

import yaml

SECRET_NAMES = (
    "gen0sec_repo_key",
    "gen0sec_api_key",
    "synapse_config_platform_api_key",
    "config.yaml.j2",
)
SECRET_RE = re.compile(r"(?<![\w.])(?:%s)(?![\w])" % "|".join(re.escape(n) for n in SECRET_NAMES))
TEMPLATE_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.S)

META_KEYS = {
    "name", "when", "tags", "register", "notify", "listen", "changed_when",
    "failed_when", "check_mode", "diff", "no_log", "ignore_errors", "until",
    "retries", "delay", "any_errors_fatal", "become", "become_user",
    "become_method", "delegate_to", "run_once", "vars", "environment",
    "loop", "with_items", "loop_control", "ignore_unreachable", "throttle",
    "timeout", "module_defaults", "args_noop",
}
BLOCK_KEYS = ("block", "rescue", "always")
DIFF_MODULES = {
    "copy", "template", "yum_repository", "lineinfile", "blockinfile",
    "ini_file", "assemble", "replace",
}
FORBIDDEN_MODULES = {
    "command", "shell", "script", "raw", "expect", "debug", "fail", "uri",
    "get_url", "pause",
}
MESSAGE_KEYS = ("fail_msg", "success_msg", "msg")


def references(value):
    if isinstance(value, str):
        return bool(SECRET_RE.search(value))
    if isinstance(value, dict):
        return any(references(k) or references(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(references(v) for v in value)
    return False


def short(module):
    return module.rsplit(".", 1)[-1]


def check_task(task, path, findings):
    if not isinstance(task, dict):
        return
    name = task.get("name", "<unnamed>")
    if any(k in task for k in BLOCK_KEYS):
        for key in BLOCK_KEYS:
            for sub in task.get(key) or []:
                check_task(sub, path, findings)
        return

    args = {k: v for k, v in task.items() if k not in META_KEYS}
    # `vars` and `environment` are real inputs to the task: scan them too.
    for extra in ("vars", "environment", "loop", "with_items"):
        if extra in task:
            args[extra] = task[extra]
    module = next((k for k in args if k not in ("args", "vars", "environment", "loop", "with_items")), None)
    if module is None or not references(args):
        return
    mod = short(module)

    def flag(rule, text):
        findings.append("%s: %s: [%s] %s" % (path, name, rule, text))

    if mod in FORBIDDEN_MODULES:
        flag("forbidden-module", "%s must not reference a secret" % mod)

    if mod == "assert":
        spec = task[module] if isinstance(task[module], dict) else {}
        for key in MESSAGE_KEYS:
            text = spec.get(key)
            if isinstance(text, str) and any(
                SECRET_RE.search(m.group(0)) for m in TEMPLATE_RE.finditer(text)
            ):
                flag("secret-in-message", "%s interpolates a secret" % key)
        # Only `that:` may reference a secret; anything else falls through to
        # the no_log rule below.
        rest = {k: v for k, v in spec.items() if k not in ("that",) + MESSAGE_KEYS}
        outside = references(rest) or references({k: v for k, v in args.items() if k != module})
        if not outside:
            return

    if task.get("no_log") is not True:
        flag("no_log", "references a secret without `no_log: true`")
    if mod in DIFF_MODULES and task.get("diff") is not False:
        flag("diff", "%s references a secret without `diff: false`" % mod)


def main(paths):
    findings = []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                tasks = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as exc:
            print("%s: cannot read: %s" % (path, exc), file=sys.stderr)
            return 2
        for task in tasks or []:
            check_task(task, path, findings)
    for line in findings:
        print(line)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
