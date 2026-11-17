import getpass
import sys

import bcrypt

from app import has_service_key, supabase_request

ADMIN_EMAIL = "chimegmaa0505@gmail.com"


def main():
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    if not has_service_key():
        raise SystemExit(
            ".env дотор SUPABASE_URL болон Supabase-ийн нууц түлхүүрээ шалгана уу."
        )

    password = getpass.getpass(
        f"{ADMIN_EMAIL} хаягийн нууц үг (8-аас доошгүй тэмдэгт): "
    )
    confirm = getpass.getpass("Нууц үгийг давтан оруулна уу: ")
    if not 8 <= len(password.encode("utf-8")) <= 72:
        raise SystemExit("Нууц үг 8-аас 72 байт урттай байх ёстой.")
    if password != confirm:
        raise SystemExit("Нууц үгнүүд таарахгүй байна.")

    existing_account = supabase_request(
        "GET",
        "users",
        params={"select": "id", "email": f"eq.{ADMIN_EMAIL}", "limit": 1},
    )
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("ascii")

    if existing_account:
        supabase_request(
            "PATCH",
            "users",
            params={"email": f"eq.{ADMIN_EMAIL}"},
            headers={"Prefer": "return=minimal"},
            json={"password_hash": password_hash},
        )
        print(f"{ADMIN_EMAIL} хэрэглэгчийн нууц үгийг шинэчиллээ.")
        return

    other_accounts = supabase_request(
        "GET",
        "users",
        params={"select": "id", "limit": 1},
    )
    if other_accounts:
        raise SystemExit(
            "Өөр хэрэглэгч бүртгэлтэй байна. "
            "Шинэ администратор нэмэхийн өмнө users хүснэгтээ шалгана уу."
        )

    supabase_request(
        "POST",
        "users",
        headers={"Prefer": "return=minimal"},
        json={"email": ADMIN_EMAIL, "password_hash": password_hash},
    )
    print(f"{ADMIN_EMAIL} хэрэглэгчийн бүртгэл үүслээ.")


if __name__ == "__main__":
    main()
