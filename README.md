# passcheck

An offline password strength checker written in Python. It scores a password
from 0 to 4 and explains what is weak about it and how to improve it.

Everything runs on your machine. The password is never stored, logged, or
sent anywhere. There are no dependencies beyond the Python standard library.

## What it checks

- Length (8, 12 and 16 character thresholds)
- Character variety: lowercase, uppercase, digits, symbols
- A built-in list of very common passwords (instant fail)
- Sequences: `abcd`, `1234`, `qwerty` and their reverses
- Repeated characters: `aaa`
- Dates and years: `19900512`, `Summer2017`
- Estimated entropy in bits, based on the character set in use

You can also point it at your own banned-password list with `--wordlist`
(for example a company policy list). The file is read from disk only.

## Usage

Run it and type the password at the hidden prompt:

```
python3 passcheck.py
```

Or pass the password directly (it will warn you, since arguments can end up
in your shell history):

```
python3 passcheck.py "correct horse battery staple"
```

JSON output for scripting:

```
python3 passcheck.py --json
```

Use a local wordlist of banned passwords, one per line:

```
python3 passcheck.py --wordlist banned.txt
```

Example output:

```
Verdict:  strong (3/4)
Entropy:  ~97.2 bits
Findings:
  - no obvious weaknesses found
Suggestions:
  - store it in a password manager and enable 2FA
```

## Tests

```
python3 -m unittest -v test_passcheck
```

19 tests cover the scoring rules and the command line interface.

## Notes

A checker like this gives a rough estimate, not a guarantee. Real strength
depends on how the password was chosen. A long passphrase of random words
beats a short string full of symbol tricks. Use a password manager and turn
on two-factor authentication where you can.

## License

MIT
