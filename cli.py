import argparse

def build_cli():
    parser = argparse.ArgumentParser(description="Password Manager")
    subparsers = parser.add_subparsers(dest="command")

    add_parser = subparsers.add_parser("add", help="Adds a new password")
    add_parser.add_argument("name", type=str, help="The name of the password entry")
    add_parser.add_argument("password", type=str, help="The password")

    get_parser = subparsers.add_parser("get", help="Retrieves a password")
    get_parser.add_argument("name", type=str, help="The name of the password entry")

    return parser
