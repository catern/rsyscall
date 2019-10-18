dir="$(mktemp --directory)"
cat >"$dir/bootstrap"
chmod +x "$dir/bootstrap"
cd "$dir" || exit 1
echo "$dir"
exec "$dir/bootstrap" socket
