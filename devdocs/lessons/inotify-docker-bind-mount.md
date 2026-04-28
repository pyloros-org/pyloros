# inotify across Docker bind-mounts: file vs. directory

## Symptom

The proxy's `notify`-based file watcher does not fire when a host editor
saves the bind-mounted `config.toml` inside a Docker container. Reloads
never happen until the container is restarted.

## Root cause

Docker bind-mounts are inode-bound at mount time. Two distinct problems
combine for the single-file case:

1. **inotify on the parent dir inside the container watches the wrong
   directory.** The container's `/etc/pyloros/` is on the container's own
   filesystem, not the host's; only the single file is bind-mounted in.
   Renames or creates that the host editor performs in *its* parent dir
   never become inotify events on the container's parent dir.

2. **Atomic-rename saves detach the bind-mount entirely.** When the host
   does `mv -f tmp config.toml`, the directory entry on the host now
   points to a *new* inode, but the container's bind-mount still
   references the original inode (which lives on as long as the bind
   holds a reference). The container literally cannot see the new
   contents — no inotify or polling strategy inside the container can
   recover from this.

In-place rewrites (`cat > config.toml`, `truncate + write`) preserve the
inode and therefore *are* visible across the bind-mount, but inotify
still does not fire because of (1).

## Verification (May 2026)

Quick host test confirms only in-place rewrites propagate:

    docker run --rm -d --name x -v $TMP/file.txt:/data/file.txt:ro alpine sleep 30
    echo REWRITTEN > $TMP/file.txt          # container sees REWRITTEN
    echo RENAMED > $TMP/new && mv -f $TMP/new $TMP/file.txt   # container still sees REWRITTEN

## Fix in this codebase

`src/proxy/server.rs` runs both the inotify watcher and a 2-second
content-hash polling thread (`spawn_file_poller`). The poller catches
in-place rewrites where inotify is silent. Both feed the same
`reload_tx` channel; the reload path is idempotent so duplicate fires
are harmless.

## Recommended user workaround for atomic-rename saves

Bind-mount the *directory* containing `config.toml`, not the single
file. Then renames within that directory are visible to the container,
and inotify on the container's parent dir works correctly:

    volumes:
      - ./pyloros-conf:/etc/pyloros/conf:ro
    command: [..., --config, /etc/pyloros/conf/config.toml]

This is the only way to get full live reload coverage when users edit
with vim / VS Code / any editor that does atomic-rename saves.
