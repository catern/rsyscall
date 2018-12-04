if test -n "$XDG_RUNTIME_DIR";
then tmp="$XDG_RUNTIME_DIR";
elif test -n "$TMPDIR";
then tmp="$TMPDIR";
else tmp=/tmp
fi
dir="$(mktemp --directory --tmpdir="$tmp")"
cat >"$dir/bootstrap"
chmod +x "$dir/bootstrap"
cd "$dir" || exit 1
echo "HELLO IM ECHOING" >&2
ls -l /proc/self/fd >&2
echo "$dir"
exec "$dir/bootstrap" socket
