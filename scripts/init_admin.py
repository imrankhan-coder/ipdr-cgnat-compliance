#!/usr/bin/env python3
# IPDR — CGNAT Compliance & Lawful-Intercept Platform
# Copyright (C) 2026 Muhammad Imran Khan (@imrankhan-coder)
# Licensed under AGPL-3.0. See LICENSE.
"""
init_admin.py — create or reset the admin user for an IPDR install.

Run after applying the schema:
    IPDR_ENV=/opt/ipdr/.env python3 scripts/init_admin.py

Reads DATABASE_URL from the env file (or the DATABASE_URL environment
variable), prompts for a username and password, and creates (or updates)
an admin account with a securely hashed password. Use this to replace the
default 'admin'/'changeme' account shipped in 00_core.sql.
"""
import os
import sys
import getpass

try:
    import psycopg2
except ImportError:
    sys.exit("psycopg2 is required: pip install psycopg2-binary")

try:
    from werkzeug.security import generate_password_hash
except ImportError:
    sys.exit("werkzeug is required (installed with Flask)")


def load_database_url():
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    env_path = os.environ.get("IPDR_ENV", "/opt/ipdr/.env")
    try:
        for line in open(env_path):
            line = line.strip()
            if line.startswith("DATABASE_URL="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    sys.exit(
        "Could not find DATABASE_URL. Set it in the environment or in "
        f"{env_path} (or point IPDR_ENV at your .env)."
    )


def main():
    url = load_database_url()
    conn = psycopg2.connect(url)
    conn.autocommit = True
    cur = conn.cursor()

    print("=== Create / reset an IPDR admin user ===")
    username = input("Username [admin]: ").strip() or "admin"
    full_name = input("Full name [System Administrator]: ").strip() or "System Administrator"

    pw1 = getpass.getpass("Password: ")
    if len(pw1) < 10:
        sys.exit("Please choose a password of at least 10 characters.")
    pw2 = getpass.getpass("Confirm password: ")
    if pw1 != pw2:
        sys.exit("Passwords do not match.")

    pw_hash = generate_password_hash(pw1)

    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    row = cur.fetchone()
    if row:
        cur.execute(
            "UPDATE users SET password_hash = %s, full_name = %s, "
            "role = 'admin', is_active = true WHERE username = %s",
            (pw_hash, full_name, username),
        )
        print(f"\nUpdated existing user '{username}' (now admin, password reset).")
    else:
        cur.execute(
            "INSERT INTO users (username, password_hash, full_name, role, is_active) "
            "VALUES (%s, %s, %s, 'admin', true)",
            (username, pw_hash, full_name),
        )
        print(f"\nCreated admin user '{username}'.")

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
