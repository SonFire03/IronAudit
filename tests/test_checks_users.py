from ironaudit.checks import users


def test_users_flags_blank_passwords(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_read(path):  # type: ignore[no-untyped-def]
        if str(path) == "/etc/passwd":
            return "root:x:0:0:root:/root:/bin/bash\nuser1:x:1000:1000:User:/home/user1:/bin/bash\n"
        if str(path) == "/etc/group":
            return "sudo:x:27:user1\n"
        if str(path) == "/etc/shadow":
            return "root::19000:0:99999:7:::\nuser1:$6$hash:19000:0:99999:7:::\n"
        return None

    monkeypatch.setattr(users, "safe_read_text", fake_read)
    findings = users.run()
    assert any(item.title == "Accounts with blank password hashes detected" for item in findings)


def test_users_unsupported_shadow(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_read(path):  # type: ignore[no-untyped-def]
        if str(path) == "/etc/passwd":
            return "root:x:0:0:root:/root:/bin/bash\n"
        if str(path) == "/etc/group":
            return None
        if str(path) == "/etc/shadow":
            return None
        return None

    monkeypatch.setattr(users, "safe_read_text", fake_read)
    findings = users.run()
    assert any(item.status == "unsupported" for item in findings)
