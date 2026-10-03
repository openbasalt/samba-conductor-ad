#!/usr/bin/env bash
# Runs ON the lab host, started by lab-test.sh. Loads the lab
# secrets into the test environment, runs the ad tests here and the
# sambatool tests as root on dc1.
set -uo pipefail
LAB_HOME="${CONDUCTOR_LAB_HOME:-$HOME/conductor-lab}"
DIR="$HOME/samba-conductor-labtest"
DC1=10.93.0.10
DC2=10.93.0.11
set -a
# shellcheck disable=SC1091
. "$LAB_HOME/secrets.env"
set +a
SSH="ssh -i $LAB_HOME/id_ed25519 -o BatchMode=yes -o UserKnownHostsFile=$LAB_HOME/known_hosts -o LogLevel=ERROR"

export AD_LAB_REALM=LAB.CONDUCTOR.TEST
export AD_LAB_DNS="$DC1,$DC2"
export AD_LAB_CA="$LAB_HOME/ca.pem"
export AD_LAB_ADMIN_USER=lab.admin
export AD_LAB_ADMIN_PASSWORD="$LAB_TESTADMIN_PASSWORD"
export AD_LAB_USER_PASSWORD="$LAB_USER_PASSWORD"
export AD_LAB_HELPDESK_PASSWORD="$LAB_HELPDESK_PASSWORD"
export AD_LAB_DC1_STOP="$SSH debian@$DC1 sudo systemctl stop samba-ad-dc"
# Starting returns before Samba listens; wait for LDAP and LDAPS.
WAIT_UP='for i in $(seq 60); do ss -ltn | grep -q ":636 " && ss -ltn | grep -q ":389 " && exit 0; sleep 1; done; exit 1'
export AD_LAB_DC1_START="$SSH debian@$DC1 'sudo systemctl start samba-ad-dc && $WAIT_UP'"
unset LAB_ADMIN_PASSWORD LAB_TESTADMIN_PASSWORD LAB_USER_PASSWORD LAB_HELPDESK_PASSWORD

cd "$DIR" || exit 1
echo "=== ad package (on $(hostname -s), Go test binary)"
./ad.test -test.v -test.count=1 -test.run "${RUN:-Lab}"
rc_ad=$?

# Make sure dc1 is up again even if the failover test was interrupted.
$SSH "debian@$DC1" "sudo systemctl is-active --quiet samba-ad-dc || sudo systemctl start samba-ad-dc; $WAIT_UP"

echo "=== sambatool package (on dc1 as root)"
$SSH "debian@$DC1" 'umask 077; cat > /tmp/sambatool.test; chmod 700 /tmp/sambatool.test' <sambatool.test
printf 'AD_LAB_SAMBATOOL=1\nAD_LAB_REALM=%s\nAD_LAB_ADMIN_USER=%s\nAD_LAB_ADMIN_PASSWORD=%s\n' \
  "$AD_LAB_REALM" "$AD_LAB_ADMIN_USER" "$AD_LAB_ADMIN_PASSWORD" |
  $SSH "debian@$DC1" "sudo bash -c 'set -a; . /dev/stdin; set +a; cd /tmp && ./sambatool.test -test.v -test.count=1 -test.run \"${RUN:-Lab}\"; rc=\$?; rm -f /tmp/sambatool.test; exit \$rc'"
rc_st=$?
echo "=== exit: ad=$rc_ad sambatool=$rc_st"
[ "$rc_ad" = 0 ] && [ "$rc_st" = 0 ]
