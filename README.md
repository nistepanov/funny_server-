# my_vpn

A small self-hosted VPN, run for personal use by a handful of people.

This repository holds the scripts, service definitions, schedules and
configuration that keep it running. It carries no secrets: keys, tokens,
identifiers, addresses and names are supplied by each deployment in local files
that are not tracked here.

## Layout

```
shared/     parts that are identical on every machine
hosts/      one directory per machine, mirroring what it runs
desktop/    optional helpers for a Linux desktop client
```

Where machines run the same thing, the file lives under `shared/` and each host
directory links to it, so a fix cannot land on one machine and miss the other.
Anything that genuinely differs stays a real file in that host's directory.

## Configuration

Nothing in the code knows which deployment it belongs to. Each machine reads its
own identity and its own inventory from local settings files; the examples in
`shared/settings/` show the shape they take. A missing or malformed file stops a
script with a clear message rather than letting it serve something wrong.

## Note

This is a personal setup, published for reference rather than for reuse. It does
nothing useful without its own configuration, certificates and credentials.
