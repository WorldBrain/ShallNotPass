# ShallNotPass

A small macOS approval and credential boundary for agent-requested commands.

The root-owned Swift helper does not understand Supabase migrations, SQL, linking, deployment state, or provider workflows. The agent remains responsible for inspecting state and constructing the exact command. The guard displays that request, asks the device owner to approve it, substitutes explicitly requested Keychain credentials internally, and executes the approved argument vector without a shell.

## Intent and limitations

ShallNotPass is a deliberately narrow boundary for agent-requested access to a Supabase instance. Its intent is to keep an agent from receiving unmediated destructive capability: selected destructive operations are rejected outright, while mutating Supabase commands must be shown to—and approved by—the macOS device owner through system authentication (a password or Touch ID, when available).

The policy can be extended for a particular environment by adapting `HardDenialPolicy`: add forbidden executables, Supabase arguments, SQL patterns, or tightly defined read-only commands that match the environment's threat model. Treat every such change as a security-sensitive policy decision and review the resulting command surface carefully.

This project is intended as a small, inspectable example and source of inspiration for similar approval boundaries. It is not a definitive security implementation, a complete database policy engine, or a substitute for least-privilege credentials, backups, access controls, monitoring, and independent security review.

## Build from source

Requirements:

- macOS 13 or later;
- Xcode Command Line Tools (`xcode-select --install`);
- a Developer ID Application signing identity to install the protected helper;
- the [Supabase CLI](https://supabase.com/docs/guides/local-development/cli/getting-started) for the commands you plan to guard.

Clone the repository, then build the release helper:

```bash
git clone https://github.com/WorldBrain/ShallNotPass.git
cd ShallNotPass
swift build -c release
./bin/supabase-ops-guard help
```

The unsigned build product is `.build/release/supabase-ops-guard-helper`. The wrapper in `bin/` uses that local build while developing.

## Sign and install

The installer requires a locally available Developer ID Application identity. List the available identities with:

```bash
security find-identity -v -p codesigning
```

Set the identity to use, then install:

```bash
export SOG_CODESIGN_IDENTITY='Developer ID Application: Your Name (TEAMID)'
./install.sh
```

The installer builds, signs, and verifies the helper, then uses `sudo` to install the signed helper at `/usr/local/libexec/supabase-ops-guard/` and the command wrapper at `/usr/local/bin/supabase-ops-guard`. Enter the administrator password yourself in a trusted terminal; it is never passed to the installer.

Verify the installed command:

```bash
supabase-ops-guard help
```

To remove it later, delete both installed paths from a trusted terminal:

```bash
sudo rm -f /usr/local/bin/supabase-ops-guard
sudo rm -rf /usr/local/libexec/supabase-ops-guard
```

## Configure a profile

```bash
supabase-ops-guard setup production
```

The current setup stores a Supabase project URL, service-role key, and optional database URL in the macOS Keychain. Secrets are never printed. When a profile already has a value, press Return to keep it; enter a value only to replace it.

## Approve an exact command

```bash
supabase-ops-guard exec production /path/to/project -- \
  supabase db push --db-url '{{database-url}}'
```

The guard prints the working directory and exact command before requesting macOS device-owner authentication. Credential placeholders must occupy a complete argument; embedded or unknown placeholders are rejected.

The following Supabase read-only commands pass through without device-owner authentication:

- `supabase status`
- `supabase migration list`
- `supabase functions list`
- `supabase projects list`
- `supabase db diff`
- `supabase inspect db`
- `supabase gen types`

Read-only commands cannot request Keychain credential placeholders. Only mutating Supabase commands retain the approval prompt; non-Supabase commands pass through without device-owner authentication.

Supported placeholders:

- `{{project-url}}`
- `{{service-role-key}}`
- `{{database-url}}`

The helper uses `Process` with an argument vector rather than a shell, so shell operators and substitutions have no special meaning unless the explicitly approved executable is itself a shell.

## Permanent denials

The following requests are rejected before an authentication prompt and cannot be approved:

- `supabase db reset` and other Supabase reset forms;
- direct `DROP TABLE`, `DROP SCHEMA`, `DROP DATABASE`, or `TRUNCATE` SQL;
- shells, language interpreters, and direct SQL clients that could conceal those operations.

Database resets and table deletion must be performed manually through the Supabase web application.

## Extend the blocklists and approval policy

The guard's policy is compiled into `HardDenialPolicy` in `Sources/SupabaseOpsGuard/main.swift`. Start by writing down the operation to prevent, the executable and arguments an agent could use to request it, and any alternate forms that could bypass a narrow match. Keep the policy specific: an overly broad rule can block legitimate operational work, while an incomplete rule can leave a bypass.

Choose the policy surface that matches the request:

- `forbiddenExecutables` rejects an executable before any approval prompt. Add shells, interpreters, database clients, or other tools that could hide an operation the approval screen should not permit.
- `forbiddenSupabaseArguments` rejects matching Supabase CLI arguments regardless of their order. Add a command argument here when that operation must never be approved through the guard.
- `forbiddenSQLPatterns` rejects destructive SQL forms after SQL comments are removed. Add a carefully scoped, case-insensitive regular expression when a direct SQL operation must never be approved.
- `readOnlySupabaseCommands` defines the small set of Supabase argument prefixes allowed without device-owner authentication. Add an entry only after establishing that the complete command family cannot mutate state or request a Keychain credential. Adding a prefix here removes the approval prompt for matching commands.

After changing policy, build the helper and inspect the behavior against a non-production project before installing it for real use:

```bash
swift build -c release
./bin/supabase-ops-guard help
```

When the changed policy is ready to install, sign and install the rebuilt helper using the normal process:

```bash
export SOG_CODESIGN_IDENTITY='Developer ID Application: Your Name (TEAMID)'
./install.sh
```

Do not rely on the guard alone to make a destructive action safe. Keep production credentials least-privileged, retain backups and recovery procedures, and have a person review the exact requested command before approving it.

## Boundary

Apart from the compiled `HardDenialPolicy`, the guard deliberately makes no judgment about whether a requested command is a valid migration, safe SQL, the right deployment operation, or properly ordered. That analysis belongs to the requesting agent and remains visible in the conversation. The guard provides only:

1. an exact request display;
2. pass-through for non-Supabase commands and explicitly classified Supabase reads, or macOS device-owner approval for Supabase mutations;
3. protected credential substitution;
4. execution and exit-status reporting.
