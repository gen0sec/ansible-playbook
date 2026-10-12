#!/usr/bin/env python3
"""Static check of the secret protections in role task files.

Usage: check_secret_protections.py FILE.yml [FILE.yml ...]
Exit 0 when every file is clean, 1 when a rule is broken (one line per
finding, "file: task name: [rule] explanation"), 2 on a file that cannot be
read. Run by test/secret_protections.sh, which is part of `make test`.

A task "references a secret" when the name of one of SECRET_NAMES, or the name
of a secret-bearing template, appears anywhere in its arguments, at any depth (strings, lists, dicts, nested
blocks). A template is secret-bearing when its text names one of SECRET_NAMES;
the templates looked at are those in the `templates` directory of the role the
task file belongs to (`../templates` from `tasks/` or `handlers/`, and
`templates` next to the file, which the fixtures use). The task keywords listed in META_KEYS are not arguments: a name in
`when` or `changed_when` is evaluated but never printed, so it does not count.

Rules:
  [no_log]            a task that references a secret has the literal
                      `no_log: true`. Does not apply to fail and assert (see
                      below), which print only their message.
  [diff]              a copy, template, yum_repository or other file-writing
                      module that references a secret also has the literal
                      `diff: false`, because --diff prints file content even
                      where no_log would hide the result.
  [forbidden-module]  command, shell, script, raw, expect, uri, get_url and
                      pause never reference a secret: they put it on a command
                      line, in a process list or in a message. Neither does
                      debug, which prints what it is given: any reference,
                      prose included, is flagged.
  [secret-in-message] fail and assert print only their message, so a secret
                      in `when:`, `failed_when:` or an assert's `that:` is
                      evaluated but never printed and is allowed, for
                      instance as an emptiness test. What is flagged is a
                      secret inside `{{ }}` or `{% %}` in msg, fail_msg or
                      success_msg. A plain mention of the variable's name in
                      prose is not an interpolation and passes. A secret in
                      the `vars`, `environment` or loop of such a task still
                      needs `no_log: true`.
"""
import glob
import os
import re
import sys

import yaml

SECRET_NAMES = (
    "gen0sec_repo_key",
    "gen0sec_api_key",
    "synapse_config_platform_api_key",
)


def name_re(names):
    return re.compile(r"(?<![\w.])(?:%s)(?![\w])" % "|".join(re.escape(n) for n in names))


SECRET_RE = name_re(SECRET_NAMES)
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
    "command", "shell", "script", "raw", "expect", "uri",
    "get_url", "pause",
}
MESSAGE_ONLY_MODULES = {"fail", "assert"}
MESSAGE_KEYS = ("fail_msg", "success_msg", "msg")


def secret_templates(path):
    """Names of the templates beside the task file that render a secret."""
    found = []
    base = os.path.dirname(os.path.abspath(path))
    for tdir in (os.path.join(base, "..", "templates"), os.path.join(base, "templates")):
        for tpl in sorted(glob.glob(os.path.join(tdir, "*"))):
            try:
                with open(tpl, encoding="utf-8") as fh:
                    text = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            if SECRET_RE.search(text):
                found.append(os.path.basename(tpl))
    return found


def references(value, rx=SECRET_RE):
    if isinstance(value, str):
        return bool(rx.search(value))
    if isinstance(value, dict):
        return any(references(k, rx) or references(v, rx) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(references(v, rx) for v in value)
    return False


def short(module):
    return module.rsplit(".", 1)[-1]


def check_task(task, path, findings, rx=SECRET_RE):
    if not isinstance(task, dict):
        return
    name = task.get("name", "<unnamed>")
    if any(k in task for k in BLOCK_KEYS):
        for key in BLOCK_KEYS:
            for sub in task.get(key) or []:
                check_task(sub, path, findings, rx)
        return

    args = {k: v for k, v in task.items() if k not in META_KEYS}
    # `vars` and `environment` are real inputs to the task: scan them too.
    for extra in ("vars", "environment", "loop", "with_items"):
        if extra in task:
            args[extra] = task[extra]
    module = next((k for k in args if k not in ("args", "vars", "environment", "loop", "with_items")), None)
    if module is None or not references(args, rx):
        return
    mod = short(module)

    def flag(rule, text):
        findings.append("%s: %s: [%s] %s" % (path, name, rule, text))

    if mod == "debug":
        flag("forbidden-module", "debug must not reference a secret")

    if mod in FORBIDDEN_MODULES:
        flag("forbidden-module", "%s must not reference a secret" % mod)

    if mod in MESSAGE_ONLY_MODULES:
        spec = task[module] if isinstance(task[module], dict) else {}
        for key in MESSAGE_KEYS:
            text = spec.get(key)
            if isinstance(text, str) and any(
                rx.search(m.group(0)) for m in TEMPLATE_RE.finditer(text)
            ):
                flag("secret-in-message", "%s interpolates a secret" % key)
        outside = references({k: v for k, v in args.items() if k != module}, rx)
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
        rx = name_re(SECRET_NAMES + tuple(secret_templates(path)))
        for task in tasks or []:
            check_task(task, path, findings, rx)
    for line in findings:
        print(line)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
