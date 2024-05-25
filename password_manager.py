import os
import getpass
from cli import build_cli
from storage import PasswordManager, generate_key

def main():
    parser = build_cli()
    args = parser.parse_args()

    master_password = getpass.getpass("Enter your master password: ")
    salt = b'salt_'  # This should be stored securely
    key = generate_key(master_password, salt)

    manager = PasswordManager(key)
    manager.load_from_file("passwords.json")

    if args.command == "add":
        name = args.name
        password = args.password
        manager.add_password(name, password)
        manager.save_to_file("passwords.json")
        print("Password added.")
    elif args.command == "get":
        name = args.name
        password = manager.get_password(name)
        if password:
            print(f"Password: {password}")
        else:
            print("Password not found.")

if __name__ == "__main__":
    main()
