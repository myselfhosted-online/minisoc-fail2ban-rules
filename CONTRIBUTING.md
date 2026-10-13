# Contributing

Contributions are welcome.

## Rule contributions

A useful rule contribution should include:

- the behavior being detected;
- why it is malicious or suspicious;
- expected severity;
- at least one malicious fixture;
- at least one benign regression fixture when practical;
- notes about false-positive risk.

## Important principles

- Behavior is the indicator. IP ownership is context.
- Do not create ASN, cloud-provider, or country blocklists.
- Do not ban only because of User-Agent text.
- Prefer exact/high-confidence paths before broad regex families.
- Treat samples as evidence and rules as policy.
- Remove secrets, credentials, private headers, cookies, and unrelated personal data.

## Severity

- **HIGH** — secret/credential discovery, repository disclosure, known webshell/backdoor hunting, or exploit probing.
- **MEDIUM** — suspicious reconnaissance requiring context.
- **INFO** — context-only signal.

## Testing

Run:

```bash
./scripts/validate.sh
```

and, on a host with Fail2Ban installed:

```bash
sudo ./install/test.sh
```
