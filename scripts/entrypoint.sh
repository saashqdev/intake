#!/bin/sh
set -e

# # Make sure directories exist
# mkdir -p /var/run/tailscale
# mkdir -p /var/lib/tailscale

# Start tailscaled in background
tailscaled --tun=linux --socket=/var/run/tailscale/tailscaled.sock &

# Give tailscaled time to come up
sleep 2

# Join Tailscale as an ephemeral node
tailscale up --authkey="${1}" --hostname "intake" --accept-dns

# /usr/sbin/sshd
# On container stop, log out of Tailscale
trap 'echo "Logging out of Tailscale..."; tailscale logout; exit 0' TERM INT

readonly PRIMARY='\033[38;2;120;66;242m'
readonly NC='\033[0m'

{
    printf '%b\n' \
    '                                                  ' \
    '                       ****                       ' \
    '                     *******                      ' \
    '                    ********                      ' \
    '                   +++*****                       ' \
    '                  ++++++++                        ' \
    '                +++++++++   ++***                 ' \
    '                +++++++    +++++**                ' \
    '              =+++++++   ++++++++                 ' \
    '             =====+++   ++++++++   ++             ' \
    '            ========   ++++++++   ++++            ' \
    '           ========  ===++++++  +++++++           ' \
    '         =========  =======++  +++++++++          ' \
    '        ========   ========    +++++++++++        ' \
    '       ----====   ========   ====++++++++++       ' \
    '      -------=   ========   ========++++++++      ' \
    '     ------------======    ========  ==++++++     ' \
    '   -----------------==-   ========  ======++++    ' \
    '   ------------------     =======  ==========++   ' \
    '    ----------------       -==-    ===========    ' \
    '                                                  ' \
    "     ${PRIMARY}█████ ███████████ ████${NC}                          " \
    "    ${PRIMARY}░░███ ░░███░░░░░░█░░███${NC}                          " \
    "  ${PRIMARY}███████  ░███   █ ░  ░███   ██████  █████ ███ █████${NC}" \
    " ${PRIMARY}███░░███  ░███████    ░███  ███░░███░░███ ░███░░███${NC} " \
    "${PRIMARY}░███ ░███  ░███░░░█    ░███ ░███ ░███ ░███ ░███ ░███${NC} " \
    "${PRIMARY}░███ ░███  ░███  ░     ░███ ░███ ░███ ░░███████████${NC}  " \
    "${PRIMARY}░░████████ █████       █████░░██████   ░░████░████${NC}   " \
    " ${PRIMARY}░░░░░░░░ ░░░░░       ░░░░░  ░░░░░░     ░░░░ ░░░░${NC}    " \
    '' \
    '=====================================================' \
    '             🚀 Welcome to inTake! 🚀' \
    '          A lightweight developer PaaS  ' \
    '             powered by ⚙️ Dokku' \
    '' \
    '        🌐 Website:    https://gointake.ca  ' \
    '        🧪 Dashboard:  https://app.gointake.ca  '
    printf '%b\n' \
    '====================================================='
}

tailscale status | awk '
{
  status = ($NF == "-" ? "online" : "offline")
  if ($2 ~ /^vmi/) {
    intake[status]++
  } else if ($2 ~ /^dfi/) {
    custom[status]++
  }
}
END {
  printf "\ninTake servers:\n"
  printf "🟢 Online devices:  %d\n", intake["online"] + 0
  printf "🔴 Offline devices: %d\n", intake["offline"] + 0

  printf "\ncustom servers:\n"
  printf "🟢 Online devices:  %d\n", custom["online"] + 0
  printf "🔴 Offline devices: %d\n", custom["offline"] + 0
}'


# Run your Next.js app
exec node server.js
