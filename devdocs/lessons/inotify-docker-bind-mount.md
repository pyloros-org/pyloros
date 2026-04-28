# inotify across Docker bind-mounts: file vs. directory

## Symptom

The proxy's `notify`-based file watcher does not fire when a host editor
saves a *single-file* bind-mounted `config.toml` inside a Docker
container. Reloads never happen until the container is restarted.

## Root cause

Docker bind-mounts are inode-bound at mount time. With a single-file
mount (`-v /host/file:/container/file`), two distinct problems combine:

1. **inotify on the parent dir inside the container watches the wrong
   directory.** The container's `/etc/pyloros/` is on the container's
   own filesystem, not the host's; only the single file is bind-mounted
   in. Renames or creates that the host editor performs in *its* parent
   dir never become inotify events on the container's parent dir.

2. **Atomic-rename saves detach the bind-mount entirely.** When the
   host does `mv -f tmp config.toml`, the directory entry on the host
   now points to a *new* inode, but the container's bind-mount still
   references the original inode. The container literally cannot see
   the new contents.

In-place rewrites (`cat > config.toml`) preserve the inode and so are
visible across the file mount, but inotify still does not fire because
of (1).

## Fix: bind-mount the directory, not the file

Bind-mount the *directory* containing `config.toml`:

    volumes:
      - ./conf:/etc/pyloros/conf:ro
    command: [..., --config, /etc/pyloros/conf/config.toml]

With a directory mount the container's `/etc/pyloros/conf` *is* the
host directory (same inode). Both editor save patterns propagate, and
inotify on that directory in the container sees the events:

    # Empirical check (May 2026):
    docker run --rm -d --name x -v $TMP:/etc/conf:ro alpine \
        sh -c 'apk add -q inotify-tools; \
               inotifywait -m -e modify -e create -e moved_to /etc/conf'
    echo NEW1 > $TMP/config.toml          # → MODIFY config.toml
    echo NEW2 > $TMP/config.toml.new && mv -f $TMP/config.toml.new $TMP/config.toml
    # → CREATE config.toml.new, MODIFY config.toml.new, MOVED_TO config.toml

The proxy's existing inotify watcher in `spawn_file_watcher` already
handles all three event kinds, so directory bind-mount + the existing
watcher is the complete fix. No polling needed.

## Other workarounds

- `docker compose restart proxy` re-runs the bind-mount setup against
  the current host path, so it picks up post-rename contents. Quick
  break-glass for users with a file-only mount, but breaks in-flight
  connections.
