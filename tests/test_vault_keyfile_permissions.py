"""tests/test_vault_keyfile_permissions.py — security audit finding #13.

vault_keyfile.json holds the wrapped data-encryption key material. It used to
be created with the process default mode (world-readable under a normal
umask) inside a ~/.peerc directory created the same way, and it was written
through the fixed, guessable name `vault_keyfile.json.tmp`, so a symlink
planted there redirected the write. The file is now private to the user, the
temporary file has a random name and is never reached through a planted
symlink, and a failed write leaves neither a temp file nor a damaged keyfile.
"""

import os
import stat

import pytest

from core.vault import keyfile
from core.vault.keyfile import create_vault, load_vault_keyfile, save_vault_keyfile

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")


@pytest.fixture(scope="module")
def sample_keyfile(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("seed") / "vault_keyfile.json")
    kf, _recovery = create_vault("correct horse battery staple", path=path)
    return kf


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_keyfile_is_private_to_the_user(tmp_path, sample_keyfile):
    path = str(tmp_path / "vault_keyfile.json")
    save_vault_keyfile(sample_keyfile, path)
    assert mode(path) == 0o600


def test_a_directory_created_for_the_keyfile_is_private(tmp_path, sample_keyfile):
    path = str(tmp_path / "newdir" / "vault_keyfile.json")
    save_vault_keyfile(sample_keyfile, path)
    assert mode(os.path.dirname(path)) == 0o700


def test_an_existing_keyfile_with_loose_permissions_is_tightened_on_the_next_save(tmp_path, sample_keyfile):
    path = str(tmp_path / "vault_keyfile.json")
    with open(path, "w") as fh:
        fh.write("{}")
    os.chmod(path, 0o666)
    save_vault_keyfile(sample_keyfile, path)
    assert mode(path) == 0o600
    assert load_vault_keyfile(path).passphrase_salt == sample_keyfile.passphrase_salt


def test_the_apps_default_directory_is_tightened_but_other_directories_are_left_alone(
        tmp_path, sample_keyfile, monkeypatch):
    app_dir = tmp_path / "dot-peerc"
    app_dir.mkdir()
    os.chmod(app_dir, 0o777)
    monkeypatch.setattr(keyfile, "DEFAULT_VAULT_KEYFILE", str(app_dir / "vault_keyfile.json"))
    save_vault_keyfile(sample_keyfile, str(app_dir / "vault_keyfile.json"))
    assert mode(app_dir) == 0o700

    other = tmp_path / "somebody-elses-dir"
    other.mkdir()
    os.chmod(other, 0o755)
    save_vault_keyfile(sample_keyfile, str(other / "vault_keyfile.json"))
    assert mode(other) == 0o755, "a directory the user chose is not ours to re-permission"


def test_a_symlink_planted_at_the_old_temp_name_is_not_followed(tmp_path, sample_keyfile):
    victim = tmp_path / "victim.txt"
    victim.write_text("do not touch")
    path = str(tmp_path / "vault_keyfile.json")
    os.symlink(str(victim), path + ".tmp")

    save_vault_keyfile(sample_keyfile, path)

    assert victim.read_text() == "do not touch"
    assert load_vault_keyfile(path).passphrase_salt == sample_keyfile.passphrase_salt


def test_a_failed_write_leaves_no_temp_file_and_keeps_the_previous_keyfile(tmp_path, sample_keyfile):
    path = str(tmp_path / "vault_keyfile.json")
    save_vault_keyfile(sample_keyfile, path)
    before = open(path, "rb").read()

    class Exploding:
        def to_json_dict(self):
            raise RuntimeError("disk on fire")

    with pytest.raises(RuntimeError):
        save_vault_keyfile(Exploding(), path)

    assert open(path, "rb").read() == before
    assert os.listdir(tmp_path) == ["vault_keyfile.json"], "no temp file may be left behind"
