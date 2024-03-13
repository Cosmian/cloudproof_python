# CoverCrypt Example

This example will show you the basics of policy-based encryption:

- creation of a policy
- keys generation
- messages encryption and decryption

## Run

```bash
pip install -r requirements.txt
python3 example.py
```

## Using a local KMS

```bash
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:4.13.3
# on another terminal
python3 example_kms.py
```
