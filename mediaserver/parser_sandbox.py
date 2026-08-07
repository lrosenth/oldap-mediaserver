"""Linux privilege and network boundary for hostile media parser processes."""

from __future__ import annotations

import ctypes
import errno
import os
import shutil
from dataclasses import dataclass
from pathlib import Path


PARSER_UID = 65_532
PARSER_GID = 65_532
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO = 0x00050000
PR_SET_NO_NEW_PRIVS = 38
NETWORK_SYSCALLS = (
    b"socket",
    b"socketpair",
    b"connect",
    b"bind",
    b"listen",
    b"accept",
    b"accept4",
    b"sendto",
    b"sendmsg",
    b"sendmmsg",
    b"recvfrom",
    b"recvmsg",
    b"recvmmsg",
)


class ParserSandboxError(RuntimeError):
    """Raised when the production parser boundary cannot fail closed."""


@dataclass(frozen=True, slots=True)
class ParserWorkspace:
    """Job-owned paths prepared for the low-privilege parser identity."""

    root: Path
    extraction_root: Path
    final_extraction_root: Path


@dataclass(frozen=True, slots=True)
class ParserSandbox:
    """Prepare storage and enter the fixed production parser identity.

    ``uid=None`` is reserved for host unit tests. Production construction uses
    :meth:`production`, which requires root so the child can lose privileges
    before touching untrusted archive content.
    """

    uid: int | None = None
    gid: int | None = None
    block_network: bool = False

    @classmethod
    def production(cls) -> "ParserSandbox":
        """Return the non-configurable production security policy."""

        return cls(uid=PARSER_UID, gid=PARSER_GID, block_network=True)

    def validate_runtime(self) -> None:
        """Fail startup when the configured privilege boundary is unavailable."""

        if self.uid is None and self.gid is None and not self.block_network:
            return
        if (
            self.uid is None
            or self.gid is None
            or self.uid <= 0
            or self.gid <= 0
            or os.name != "posix"
            or not hasattr(os, "setgroups")
            or not hasattr(os, "setuid")
            or not hasattr(os, "setgid")
            or os.geteuid() != 0
        ):
            raise ParserSandboxError(
                "Production parser isolation requires a root Unix worker and "
                "non-root parser identity."
            )
        if self.block_network:
            _load_seccomp_library()

    def prepare(
        self, ingest_root: Path, quarantine: Path, sip_path: Path
    ) -> ParserWorkspace:
        """Create a retry-safe workspace accessible only to the parser UID."""

        self.validate_paths(ingest_root, quarantine, sip_path)
        workspace_root = quarantine / ".parser-work"
        final_extraction_root = quarantine / "extracted"
        _remove_owned_directory(workspace_root)
        _remove_owned_directory(final_extraction_root)
        workspace_root.mkdir(mode=0o700, exist_ok=False)

        if self.uid is not None and self.gid is not None:
            os.chown(ingest_root, -1, self.gid)
            os.chmod(ingest_root, 0o710)
            os.chown(quarantine, -1, self.gid)
            os.chmod(quarantine, 0o710)
            os.chown(sip_path, -1, self.gid)
            os.chmod(sip_path, 0o440)
            os.chown(workspace_root, self.uid, self.gid)
            os.chmod(workspace_root, 0o700)

        return ParserWorkspace(
            root=workspace_root,
            extraction_root=workspace_root / "extracted",
            final_extraction_root=final_extraction_root,
        )

    @staticmethod
    def validate_paths(ingest_root: Path, quarantine: Path, sip_path: Path) -> None:
        """Reject link or containment ambiguity before any SIP filesystem read."""

        if (
            not ingest_root.is_dir()
            or ingest_root.is_symlink()
            or not quarantine.is_dir()
            or quarantine.is_symlink()
            or quarantine.resolve().parent != ingest_root.resolve()
            or not sip_path.is_file()
            or sip_path.is_symlink()
            or sip_path.resolve().parent != quarantine.resolve()
        ):
            raise ParserSandboxError("Parser input paths are not safe files.")

    def seal_input(self, quarantine: Path, sip_path: Path) -> None:
        """Revoke parser access immediately after its process has exited."""

        if self.uid is None or self.gid is None:
            return
        if quarantine.is_dir() and not quarantine.is_symlink():
            os.chown(quarantine, -1, os.getegid())
            os.chmod(quarantine, 0o700)
        if sip_path.is_file() and not sip_path.is_symlink():
            os.chown(sip_path, -1, os.getegid())
            os.chmod(sip_path, 0o400)

    def enter_child(self) -> None:
        """Scrub credentials, drop identity, and deny network socket syscalls."""

        os.environ.clear()
        os.environ.update(
            {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "HOME": "/tmp",
            }
        )
        os.umask(0o077)
        if self.uid is not None and self.gid is not None:
            os.setgroups([])
            os.setgid(self.gid)
            os.setuid(self.uid)
            if os.geteuid() != self.uid or os.getegid() != self.gid:
                raise ParserSandboxError("Parser privilege drop did not take effect.")
        if self.block_network:
            _install_network_seccomp_filter()

    @staticmethod
    def promote(workspace: ParserWorkspace) -> Path:
        """Move successfully validated extraction into its stable job location."""

        if (
            not workspace.extraction_root.is_dir()
            or workspace.extraction_root.is_symlink()
            or workspace.final_extraction_root.exists()
            or workspace.final_extraction_root.is_symlink()
        ):
            raise ParserSandboxError("Parser extraction cannot be promoted safely.")
        workspace.extraction_root.rename(workspace.final_extraction_root)
        workspace.root.rmdir()
        return workspace.final_extraction_root


def _remove_owned_directory(path: Path) -> None:
    """Remove only an exact real directory from the current import workspace."""

    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_dir():
        raise ParserSandboxError("Parser workspace path is not a safe directory.")
    shutil.rmtree(path)


def _load_seccomp_library() -> ctypes.CDLL:
    """Load libseccomp with explicit signatures or fail closed."""

    try:
        library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    except OSError as error:
        raise ParserSandboxError(
            "libseccomp is required for parser isolation."
        ) from error
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    library.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    library.seccomp_rule_add.restype = ctypes.c_int
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int
    return library


def _install_network_seccomp_filter() -> None:
    """Apply an inherited allow-by-default filter denying network creation/use."""

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise ParserSandboxError("Could not set no-new-privileges for parser.")
    library = _load_seccomp_library()
    context = library.seccomp_init(SCMP_ACT_ALLOW)
    if not context:
        raise ParserSandboxError("Could not initialize parser seccomp policy.")
    try:
        denied_action = SCMP_ACT_ERRNO | errno.EPERM
        for name in NETWORK_SYSCALLS:
            syscall = library.seccomp_syscall_resolve_name(name)
            if (
                syscall >= 0
                and library.seccomp_rule_add(context, denied_action, syscall, 0) != 0
            ):
                raise ParserSandboxError("Could not build parser seccomp policy.")
        if library.seccomp_load(context) != 0:
            raise ParserSandboxError("Could not activate parser seccomp policy.")
    finally:
        library.seccomp_release(context)
