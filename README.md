# What is this

CredX is a program to store personal account credential in command line. The stored data is encrypted using Fernet so it is not easily accessed by irresponsible people. The program also has a login process to increase the security.

# How To Use

## Install Modules

- Python v3.11.5
- Pip v23.2.1

1. Clone this repo into your local computer. Then move inside to the cloned folder.

```bash
git clone https://github.com/ralfarishi/CredX.git
cd /CredX
```

2. Install all modules using pip.

```bash
pip install cryptography bcrypt pyfiglet colorama
```

3. Wait until the installation complete.

4. Run the `main.py` file.

5. Then, make your own configuration by choosing the first menu.

---

\*notes:

- I'm working on to make the executable for this program, so if you're not familiar with python you can use it by running the `.exe` file.
- Don't forget to regularly backup the `.pkl` file.
