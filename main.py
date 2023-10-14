import getpass, bcrypt, time, os, pickle
from cryptography.fernet import Fernet
from pyfiglet import Figlet
from colorama import Fore, Style, init


class AccountManager:
    def __init__(self, encryption_key):
        self.accounts = []
        self.encryption_key = encryption_key

    def add_account(self, account_type, username, password):
        account = {
            "Account Type": account_type,
            "Username": username,
            "Password": password,
        }
        self.accounts.append(account)
        print(f"\33[32mAkun berhasil ditambahkan.\33[0m")

    def update_account(
        self, account_index, new_account_type, new_username, new_password
    ):
        if 0 <= account_index < len(self.accounts):
            account = self.accounts[account_index]
            if new_account_type:
                account["Account Type"] = new_account_type
            if new_username:
                account["Username"] = new_username
            if new_password:
                account["Password"] = new_password
            print(f"\33[34mData akun berhasil diperbarui.\33[0m")
        else:
            print("Nomor akun tidak valid!")

    def delete_account(self, account_index):
        if account_index >= 0 and account_index < len(self.accounts):
            deleted_account = self.accounts.pop(account_index)
            print(
                f"Akun \x1B[3m\033[31m{deleted_account['Account Type']}\033[0m\x1B[0m berhasil dihapus."
            )
        else:
            print("Nomor akun tidak valid.")

    def view_accounts(self):
        if not self.accounts:
            print("Tidak ada akun yang tersedia.")
        else:
            print("\nDaftar Akun:")
            for i, account in enumerate(self.accounts, start=1):
                print(f"{i}. {account['Account Type']}")

    def get_account(self, account_index):
        if 0 <= account_index < len(self.accounts):
            return self.accounts[account_index]
        else:
            return None

    def save_to_file(self, filename):
        encrypted_data = Fernet(self.encryption_key).encrypt(
            pickle.dumps(self.accounts)
        )
        with open(filename, "wb") as file:
            file.write(encrypted_data)
            print(f"Data berhasil disimpan ke {filename}")

    def load_from_file(self, filename):
        try:
            with open(filename, "rb") as file:
                encrypted_data = file.read()
                decrypted_data = Fernet(self.encryption_key).decrypt(encrypted_data)
                self.accounts = pickle.loads(decrypted_data)
                print(f"Data berhasil dimuat dari {filename}")
        except (FileNotFoundError, pickle.UnpicklingError):
            print(f"Tambah data untuk membuat file {filename} secara otomatis.")


def save_configuration(username, hashed_password, encryption_key):
    with open("credents.pkl", "wb") as file:
        config = {
            "username": username,
            "hashed_password": hashed_password,
            "encryption_key": encryption_key,
        }
        pickle.dump(config, file)


def load_configuration():
    if os.path.exists("credents.pkl"):
        with open("credents.pkl", "rb") as file:
            config = pickle.load(file)

            return (
                config["username"],
                config["hashed_password"],
                config["encryption_key"],
            )
    return None, None, None


def main():
    filename = "accounts.pkl"
    fig = Figlet(font="slant")
    init(autoreset=True)
    encryption_key = None

    try:
        if os.path.exists("credents.pkl"):
            username, hashed_password, encryption_key = load_configuration()
            if (
                username is not None
                and hashed_password is not None
                and encryption_key is not None
            ):
                print(Fore.LIGHTBLUE_EX + Style.BRIGHT + fig.renderText("CredX Login"))
                input_username = input("Username: ")
                input_password = getpass.getpass("Password: ")

                if input_username == username and bcrypt.checkpw(
                    input_password.encode("utf-8"), hashed_password.encode("utf-8")
                ):
                    print("Loading...")
                    time.sleep(2.5)
                    print(
                        Fore.LIGHTGREEN_EX
                        + Style.BRIGHT
                        + fig.renderText("Hello, " + input_username)
                    )
                    account_manager = AccountManager(encryption_key.encode())
                    account_manager.load_from_file(filename)
                    account_manager_menu(account_manager, filename)
                else:
                    print("Loading...")
                    time.sleep(2.5)
                    print("Login gagal. Username atau password salah.")
        else:
            while True:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + fig.renderText("CredX"))
                print("Menu Utama:")
                print("1. Konfigurasi")
                print("2. Login")
                print("3. Keluar")
                choice = input("Pilih menu (1/2/3): ")

                if choice == "1":
                    if encryption_key is not None:
                        print("Konfigurasi sudah dilakukan. Menu login akan tampil.")
                    else:
                        print("Konfigurasi:")
                        new_username = input("Masukkan username: ")
                        new_password = getpass.getpass("Masukkan password: ")

                        salt = bcrypt.gensalt()
                        hashed_password = bcrypt.hashpw(new_password.encode(), salt)

                        encryption_key = Fernet.generate_key()

                        print("\n=== Hasil Konfigurasi ===")
                        print(f"Username: {new_username}")
                        print(f"Password: **secret**")

                        choice = input(
                            "Apakah Anda ingin menyimpan konfigurasi (y/n)? "
                        ).lower()
                        if choice == "y":
                            save_configuration(
                                new_username,
                                hashed_password.decode(),
                                encryption_key.decode(),
                            )
                            print("Konfigurasi berhasil disimpan.")
                        else:
                            print("Konfigurasi tidak disimpan.")

                elif choice == "2":
                    username, hashed_password, encryption_key = load_configuration()
                    if (
                        username is not None
                        and hashed_password is not None
                        and encryption_key is not None
                    ):
                        print(
                            Fore.LIGHTBLUE_EX
                            + Style.BRIGHT
                            + fig.renderText("CredX Login")
                        )
                        input_username = input("Username: ")
                        input_password = getpass.getpass("Password: ")

                        if input_username == username and bcrypt.checkpw(
                            input_password.encode("utf-8"),
                            hashed_password.encode("utf-8"),
                        ):
                            print("Loading...")
                            time.sleep(2.5)
                            print(
                                Fore.LIGHTGREEN_EX
                                + Style.BRIGHT
                                + fig.renderText("Hello, " + input_username)
                            )
                            account_manager = AccountManager(encryption_key.encode())
                            account_manager.load_from_file(filename)
                            account_manager_menu(account_manager, filename)
                        else:
                            print("Loading...")
                            time.sleep(2.5)
                            print("Login gagal. Username atau password salah.")
                    else:
                        print(
                            "Konfigurasi belum dilakukan. Silakan konfigurasi terlebih dahulu."
                        )
                elif choice == "3":
                    break
                else:
                    print("Pilihan tidak valid. Silakan coba lagi.")
    except KeyboardInterrupt:
        print("\nSampai jumpa kembali!")


def account_manager_menu(account_manager, filename):
    fig = Figlet(font="slant")

    try:
        while True:
            print("\nMenu Utama:")
            print("1. Tambah Akun")
            print("2. Update Akun")
            print("3. Lihat Akun")
            print("4. Hapus Akun")
            print("5. Simpan dan Keluar")
            choice = input("Pilih menu (1/2/3/4/5): ")

            if choice == "1":
                account_type = input("\nMasukkan jenis akun: ")
                username = input("Masukkan username: ")
                password = input("Masukkan password: ")
                account_manager.add_account(account_type, username, password)
            elif choice == "2":
                account_manager.view_accounts()
                if account_manager.accounts:
                    account_index = (
                        int(input("Pilih nomor akun yang akan di-update: ")) - 1
                    )
                    selected_account = account_manager.get_account(account_index)
                    if selected_account:
                        new_account_type = input(
                            "Masukkan jenis akun (kosongkan jika tidak ingin mengubah) : "
                        )
                        new_username = input(
                            "Masukkan username (kosongkan jika tidak ingin mengubah) : "
                        )
                        new_password = input(
                            "Masukkan password (kosongkan jika tidak ingin mengubah) : "
                        )
                        account_manager.update_account(
                            account_index, new_account_type, new_username, new_password
                        )
                    else:
                        print("Nomor akun tidak valid.")
            elif choice == "3":
                account_manager.view_accounts()
                if account_manager.accounts:
                    account_index = (
                        int(input("Pilih nomor akun yang ingin dilihat: ")) - 1
                    )
                    selected_account = account_manager.get_account(account_index)
                    if selected_account:
                        print(
                            Fore.LIGHTRED_EX
                            + Style.BRIGHT
                            + fig.renderText(selected_account["Account Type"])
                        )
                        print(f"Username: {selected_account['Username']}")
                        print(f"Password: {selected_account['Password']}")
                    else:
                        print("Nomor akun tidak valid.")
            elif choice == "4":
                account_manager.view_accounts()
                if account_manager.accounts:
                    account_index = (
                        int(input("Pilih nomor akun yang akan dihapus: ")) - 1
                    )
                    account_to_delete = account_manager.get_account(account_index)
                    if account_to_delete:
                        account_manager.delete_account(account_index)
                    else:
                        print("Nomor akun tidak valid.")
            elif choice == "5":
                account_manager.save_to_file(filename)
                break
            else:
                print("Pilihan tidak valid. Silakan coba lagi.")
    except KeyboardInterrupt:
        print("\nSampai jumpa kembali!")


if __name__ == "__main__":
    main()
