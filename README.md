# What is this

CredX is a program to store personal account credential in command line. The stored data is encrypted using Fernet so it is not easily accessed by irresponsible people. The program also has a login process to increase the security.

# How To Use

## Install Modules

- Python v3.8.10
- Pip v23.2.1

1. Clone this repo into your local computer. Then move inside to the cloned folder.

```bash
git clone https://github.com/ralfarishi/CredX.git
cd /CredX
```

2. Install all modules using pip.

```bash
pip install cryptography bcrypt pyfiglet termcolor
```

3. Wait until the installation complete.

## Generate Key

1. Open the `generate_key.py` file. There are 2 method inside the file `hashed_password()` & `encryption_key()`
2. In `hashed_password()` method, change the `password` variable value to your password string.

```py
# example
password = "secretPassword123"
```

3. Run the `generate_key.py` file.

```bash
python generate_key.py
```

4. You will see 2 outputs like the example below. The first line is your password key & the second line is the encryption key.

```bash
b'$2b$12$.xHvyKPhN1FMo/lh2.UWWeypwUwRd2xAlWuLEsCAYnkcdQfJhCeEG'
JMhBx7NRjrnyGZN0jKzuyGCSV9Y9gBKy-qbghcaVpiA=
```

## Key Configuration

1. Open the `main.py` file and find the `login()` method.
2. Copy the keys you generate earlier to the `hashed_password` & `encryption_key` variables.

```python
# example
hashed_password = b"$2b$12$.xHvyKPhN1FMo/lh2.UWWeypwUwRd2xAlWuLEsCAYnkcdQfJhCeEG"
encryption_key = b"JMhBx7NRjrnyGZN0jKzuyGCSV9Y9gBKy-qbghcaVpiA="
```

3. Now you can run & use the program.

## Optional

You can change the login username in the `login()` method. Find the `if input_username == "Potus"` code around line 88. Then change the `"Potus"` string to your username.

---

\*notes: 

- I'm working on to make the executable for this program, so if you're not familiar with python you can use it by running the `.exe` file.
- Don't forget to regularly backup the `.pkl` file.
