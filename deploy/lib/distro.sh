# shellcheck shell=bash
#
# Distribution abstraction.
#
# Everything the installer does that differs between an RPM host and a Debian
# host lives here, and nowhere else. The rest of install.sh calls these
# functions and stays readable.
#
# Two families are supported, and the code says which:
#
#   rhel    AlmaLinux, Rocky, RHEL, CentOS Stream, Fedora   (dnf)
#   debian  Debian, Ubuntu, and derivatives                 (apt-get)
#
# Anything else is refused by name rather than half-supported. A partial install
# on an untested distribution is worse than a clear refusal: it leaves a machine
# that looks protected and is not.
#
# Source it, then call `distro_detect` once before anything else.

# Populated by distro_detect.
DISTRO_ID=""        # almalinux | debian | ubuntu | ...
DISTRO_FAMILY=""    # rhel | debian
DISTRO_VERSION=""   # 9 | 12 | 24.04
DISTRO_PRETTY=""

# ---------------------------------------------------------------- detection
distro_detect() {
    [[ -r /etc/os-release ]] || return 1
    # shellcheck disable=SC1091
    . /etc/os-release

    DISTRO_ID="${ID:-unknown}"
    DISTRO_VERSION="${VERSION_ID:-}"
    DISTRO_PRETTY="${PRETTY_NAME:-${DISTRO_ID} ${DISTRO_VERSION}}"

    # ID_LIKE is the reliable signal for derivatives: Pop!_OS says
    # ID_LIKE="ubuntu debian", AlmaLinux says ID_LIKE="rhel centos fedora".
    local haystack=" ${DISTRO_ID} ${ID_LIKE:-} "
    case "$haystack" in
        *" rhel "*|*" fedora "*|*" centos "*) DISTRO_FAMILY="rhel" ;;
        *" debian "*|*" ubuntu "*)            DISTRO_FAMILY="debian" ;;
        *)
            case "$DISTRO_ID" in
                almalinux|rocky|rhel|centos|fedora) DISTRO_FAMILY="rhel" ;;
                debian|ubuntu|raspbian|linuxmint|pop) DISTRO_FAMILY="debian" ;;
                *) DISTRO_FAMILY="" ;;
            esac
            ;;
    esac
    [[ -n "$DISTRO_FAMILY" ]]
}

distro_supported() {
    [[ "$DISTRO_FAMILY" == "rhel" || "$DISTRO_FAMILY" == "debian" ]]
}

# ---------------------------------------------------------------- packages
pkg_refresh() {
    case "$DISTRO_FAMILY" in
        rhel)   dnf -q makecache >/dev/null 2>&1 || true ;;
        # Without this, a fresh Debian image has no package lists at all and
        # every install fails with "Unable to locate package".
        debian) DEBIAN_FRONTEND=noninteractive apt-get -qq update >/dev/null 2>&1 || true ;;
    esac
}

pkg_install() {
    case "$DISTRO_FAMILY" in
        rhel)
            dnf install -y "$@"
            ;;
        debian)
            # -o Dpkg::Options: keep any config file the operator already edited;
            # an installer that silently overwrites nginx.conf is a bad guest.
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                -o Dpkg::Options::=--force-confold \
                -o Dpkg::Options::=--force-confdef "$@"
            ;;
    esac
}

pkg_installed() {
    case "$DISTRO_FAMILY" in
        rhel)   rpm -q "$1" >/dev/null 2>&1 ;;
        debian) dpkg -s "$1" >/dev/null 2>&1 ;;
    esac
}

# The full package inventory, one line per package, for the pre-deploy
# snapshot that rollback reads.
#
# It used to be a bare `rpm -qa | sort ... 2>/dev/null || true` in
# lib/common.sh. On Ubuntu that wrote an EMPTY file and said nothing: the
# snapshot which is supposed to answer "what did this host have before
# Sentinel touched it" answered "no packages". Writes to stdout so the caller
# can see it fail; a caller that discards the exit code gets an empty file
# either way, which is why snapshot_create now checks the result.
pkg_list() {
    case "$DISTRO_FAMILY" in
        rhel)   rpm -qa | sort ;;
        debian) dpkg-query -W -f '${Package} ${Version} ${Architecture}\n' | sort ;;
    esac
}

# Extra repositories needed before the core packages resolve.
pkg_enable_extra_repos() {
    case "$DISTRO_FAMILY" in
        rhel)
            # EPEL carries Suricata. Missing it is degraded, not fatal.
            pkg_installed epel-release || dnf install -y epel-release >/dev/null 2>&1 || return 1
            ;;
        debian)
            # Debian and Ubuntu both ship Suricata in universe/main. Nothing extra.
            return 0
            ;;
    esac
}

# ---------------------------------------------------------------- python
#
# The floor is 3.10: the whole package compiles and its tests pass there, which
# means every current target ships a usable interpreter without extra repos —
# Ubuntu 22.04 has 3.10, Debian 12 has 3.11, AlmaLinux 9 has 3.11/3.12 in
# AppStream, Ubuntu 24.04 has 3.12. Requiring 3.12 would have forced a
# third-party repository onto two of those for no benefit.
PYTHON_MIN_MINOR=10

python_candidates() {
    case "$DISTRO_FAMILY" in
        rhel)   printf '%s\n' python3.13 python3.12 python3.11 python3 ;;
        debian) printf '%s\n' python3.13 python3.12 python3.11 python3.10 python3 ;;
    esac
}

# Echoes the best interpreter already present, or nothing.
python_find() {
    local cand minor
    while read -r cand; do
        command -v "$cand" >/dev/null 2>&1 || continue
        minor="$("$cand" -c 'import sys; print(sys.version_info[1])' 2>/dev/null)" || continue
        [[ "$minor" =~ ^[0-9]+$ ]] || continue
        (( minor >= PYTHON_MIN_MINOR )) && { printf '%s\n' "$cand"; return 0; }
    done < <(python_candidates)
    return 1
}

# Package names that provide an acceptable interpreter plus its headers.
python_pkg_names() {
    case "$DISTRO_FAMILY" in
        rhel)
            # AppStream carries both; try the newer first.
            printf '%s\n' "python3.12 python3.12-devel" "python3.11 python3.11-devel"
            ;;
        debian)
            printf '%s\n' "python3 python3-dev python3-venv"
            ;;
    esac
}

# What an interpreter that is ALREADY on the host still needs: the venv module
# and the C headers.
#
# A different question from python_pkg_names, which answers "what do I install
# when there is no usable interpreter at all". On Ubuntu that list is never
# reached — 24.04 ships python3 = 3.12.3, which clears PYTHON_MIN_MINOR — and
# yet `python3.12 -m venv` still dies with "ensurepip is not available" and
# systemd-python==235 will not compile, because python3.12-venv and
# python3.12-dev are separate packages that nothing installed. Measured on
# Ubuntu 24.04.4: `dpkg -l` showed both as `un`, i.e. never installed.
#
# The names follow the INTERPRETER, not the family default. `python3-dev` and
# `python3-venv` are metapackages pointing at whatever Debian currently calls
# the default python3; on a host where the chosen interpreter is python3.13
# they would install headers for 3.12 and the build would fail against the
# wrong Python.h without ever saying so.
#
# Takes the interpreter, echoes one package per line. Refuses (non-zero, no
# output) when the interpreter will not say which version it is — better no
# names than names for a version we guessed.
python_support_pkgs() {
    local py="$1" xy
    xy="$("$py" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)" || return 1
    [[ "$xy" =~ ^[0-9]+\.[0-9]+$ ]] || return 1
    case "$DISTRO_FAMILY" in
        # RHEL keeps ensurepip inside the interpreter package, so only the
        # headers are ever a separate install here.
        rhel)   printf '%s\n' "python${xy}-devel" ;;
        debian) printf '%s\n' "python${xy}-venv" "python${xy}-dev" ;;
    esac
}

# ---------------------------------------------------------------- core packages
#
# Same roles, different names. Kept as one function rather than a lookup table
# so the reason for each package is visible next to it.
#
# `auditd` is in the debian list and NOT in the rhel one, and that asymmetry is
# deliberate: RHEL ships auditd in its minimal install, Ubuntu ships none of it.
# Measured on Ubuntu 24.04.4 — `auditctl` did not exist, so `augenrules --load`
# was "command not found", step 37 warned once, and the install went on to
# report success. What is lost with it is every host.* detection plus
# auth.new_user and auth.new_ssh_key: sentinel_identity, sentinel_ssh,
# sentinel_cron, sentinel_systemd, sentinel_webroot, sentinel_exec,
# sentinel_priv and sentinel_cmd have nothing to load them.
#
# `audispd-plugins` is deliberately NOT here. It carries the remote/syslog
# dispatcher plugins, and Sentinel's collector reads /var/log/audit/audit.log
# directly (ingest.auditd_log_path) — it dispatches nowhere. This list is a
# `die` path, so a package that buys nothing is a way for the install to stop
# over something it does not need.
pkg_names_core() {
    case "$DISTRO_FAMILY" in
        rhel)
            printf '%s\n' \
                gcc \
                systemd-devel pkgconf-pkg-config \
                nginx nftables \
                acl ca-certificates curl tar zstd jq
            ;;
        debian)
            printf '%s\n' \
                gcc \
                libsystemd-dev pkg-config \
                nginx nftables \
                auditd \
                acl ca-certificates curl tar zstd jq
            ;;
    esac
}

# ---------------------------------------------------------------- postgresql
pg_service() {
    case "$DISTRO_FAMILY" in
        rhel)   printf 'postgresql' ;;
        # Debian runs one unit per cluster plus a wrapper target; the wrapper is
        # what you enable, and it is what survives a version upgrade.
        debian) printf 'postgresql' ;;
    esac
}

# Data directory of the cluster the installer configures.
pg_datadir() {
    case "$DISTRO_FAMILY" in
        rhel)
            printf '/var/lib/pgsql/data'
            ;;
        debian)
            # Debian versions its clusters. Take the highest that exists, which
            # is what `pg_lsclusters` would call the current one.
            local d
            d="$(find /etc/postgresql -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -V | tail -1)"
            [[ -n "$d" ]] && printf '%s/main' "$d" || printf '/etc/postgresql/main'
            ;;
    esac
}

# Where postgresql.conf and pg_hba.conf actually live (Debian splits config
# from data; RHEL keeps them together).
pg_confdir() {
    case "$DISTRO_FAMILY" in
        rhel)   printf '/var/lib/pgsql/data' ;;
        debian) pg_datadir ;;
    esac
}

pg_pkg_names() {
    case "$DISTRO_FAMILY" in
        rhel)   printf '%s\n' postgresql-server postgresql-contrib ;;
        debian) printf '%s\n' postgresql postgresql-contrib ;;
    esac
}

# Make sure an initialised cluster exists. Idempotent.
pg_bootstrap() {
    case "$DISTRO_FAMILY" in
        rhel)
            # AppStream module: pick 16 when offered, otherwise the default stream.
            dnf module enable -y postgresql:16 >/dev/null 2>&1 || true
            pkg_install $(pg_pkg_names) || return 1
            if [[ ! -f /var/lib/pgsql/data/PG_VERSION ]]; then
                postgresql-setup --initdb || return 1
            fi
            ;;
        debian)
            # The Debian package initialises a cluster in its postinst, so there
            # is nothing to initdb — doing it manually would create a second,
            # unused cluster on another port.
            pkg_install $(pg_pkg_names) || return 1
            ;;
    esac
}

# ---------------------------------------------------------------- suricata
suricata_pkg() { printf 'suricata'; }

# Where the OPTIONS/ARGS for the suricata unit are read from.
suricata_defaults_file() {
    case "$DISTRO_FAMILY" in
        rhel)   printf '/etc/sysconfig/suricata' ;;
        debian) printf '/etc/default/suricata' ;;
    esac
}

# ---------------------------------------------------------------- tls
# Where the distribution keeps certs/ and private/.
#
# /etc/pki/tls is an RPM convention. Debian and Ubuntu have no /etc/pki at all —
# confirmed on Ubuntu 24.04.4, where the directory simply does not exist — so
# the hardcoded path meant `openssl req -out /etc/pki/tls/certs/...` failed, the
# placeholder certificate was never written, and the vhost pointed at a file
# that would never be there. nginx then refuses to start on the missing
# certificate, at step 33, with an error about TLS rather than about the path.
tls_dir() {
    case "$DISTRO_FAMILY" in
        rhel)   printf '/etc/pki/tls' ;;
        debian) printf '/etc/ssl' ;;
    esac
}

# ---------------------------------------------------------------- security modules
# SELinux (rhel) and AppArmor (debian) both need a nudge for nginx to proxy to a
# local port. Neither is fatal when absent.
security_module_allow_nginx_proxy() {
    case "$DISTRO_FAMILY" in
        rhel)
            command -v setsebool >/dev/null 2>&1 && \
                setsebool -P httpd_can_network_connect 1 2>/dev/null || true
            ;;
        debian)
            # Debian's nginx profile is permissive about outbound connections by
            # default; nothing to change. Left explicit so the asymmetry is not
            # mistaken for an omission.
            true
            ;;
    esac
}

# ---------------------------------------------------------------- nginx
# Both families read /etc/nginx/conf.d/*.conf from the shipped nginx.conf, so
# the installer uses that path on both. Debian additionally has
# sites-enabled/, which we deliberately do not touch: it belongs to whatever
# the operator already runs there.
nginx_confdir() { printf '/etc/nginx/conf.d'; }
