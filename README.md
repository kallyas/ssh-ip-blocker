# ssh-ip-blocker
Block IP addresses based on SSH logs 
ssh-blocker

#### NAME
    ssh-blocker - read a log pipe and block attacks with ipset
    
#### OVERVIEW
ssh-blocker is a program that reads log lines from a named pipe (FIFO) and
tries to find IP addresses in lines containing login attempts. On a
successful login attempt, the address is added to a whitelist.

When a certain number of invalid login attempts is reached within a pre-defined
period, the address will be added to a blacklist.

The whitelist and blacklists are stored with `ipset[1]`, a relevant iptables
rule must exist that take care of it. Using ipset, the blocked address will
expire after some time.

#### REQUIREMENTS
    This program needs the following libraries:
    - libcap - for dropping privileges when running as root
    - libpcre - for matching log lines
    - libipset - for keeping a blacklist and whitelist of IP addresses

    The following programs are recommended:
    - iptables - for actual allowing or denying access based on ipset lists.
    - OpenSSH - the service to protect by reading its logs.

    One log provider must be available:
    - rsyslog - for writing log messages to the named pipe (FIFO).
    - systemd - for retrieving log messages from the systemd journal.

    Debian Wheezy has been used for testing. Older versions of the above
    software may also work, but is no guaranteed.

#### CONFIGURATION
    The file ssh-blocker.h can be changed to adapt to your configuration. Some
    interesting defaults are shown below:
    - MATCH_THRESHOLD - After 5 invalid login attempts, the IP is blocked.
    - SETNAME_WHITELIST and SETNAME_BLACKLIST - The names of the blacklist as
      used with ipset (and which can be used with iptables). Defaults to
      "ssh-whitelist" and "ssh-blacklist" respectively.
    - WHITELIST_TIME - After a successful login attempt, you are unblocked for
      3600 seconds (one hour) (in which you can perform as many invalid login
      attempts as you want).
    - BLOCK_TIME - If an IP address is blocked, it will last 3600 seconds (one
      hour).

    For more options, see the comments in ssh-blocker.h.

    Edit your sshd configuration (/etc/ssh/sshd_config) and set "UseDNS no".
    This will prevent IP addresses from being resolved to hostnames. Reload the
    SSH configuration thereafter.

    Exactly one log provider can be used, this must be specified at compile
    time.

    (for rsyslog only)
    Assuming the named pipe to be located at /run/ssh-blocker.fifo, create a new
    rsyslog configuration file (/etc/rsyslog.d/ssh-blocker.conf) containing:

        :programname,isequal,"sshd" |/run/ssh-blocker.fifo

    For best security, create a new system user, say "ssh-blocker". Its shell
    can be /sbin/nologin with /nonexistent as home directory.

    To finish, you need to perform actions in the correct order and add iptables
    rules. Continue reading the USAGE section.

#### USAGE
    There are some ways to set-up this program:
    - Manually create a FIFO before starting rsyslog, start this program
      thereafter. Alternative: start this program followed by rsyslog.  (only
      applicable in log pipe configuration)
    - Manually create the whitelist and blacklist ipsets, set iptables rules and
      start this program. Alternative: start this program and set iptables
      rules thereafter.

    The command is invoked as follows:

        ssh-blocker -d username log-pipe-file
    Or if systemd is used instead of a pipe:

        ssh-blocker -d username

    "-d" is optional, it causes the program to daemonize. This happens just
    before log entries are read, so any errors in opening the fifo, dropping
    privileges can be caught earlier. Note that "-d" can be specified only as
    the first argument, getopt is not used for now.

    "username" is the user under which the program should run. Do not run this
    program under someone like "nobody" because all "nobody" users can kill this
    program, write junk to the FIFO or ptrace it if settings/permissions allow
    it. When using the systemd (journal) source, be sure that this user is a
    member of the 'systemd-journal' group).

    (only applicable in log pipe configuration)
    "log-pipe-file" must be replaced by the path to a named pipe. If it does not
    exist at start-up, it will be created with permissions 0600 (read/write for
    owner only) under the user and group the program was started with. If the
    file already exists, it must be a FIFO that is owned by root (or the user
    that started this program) and not be world-writable.

    (only applicable in log pipe configuration)
    Suggested start-up order:
    - Start this program before rsyslog:
        ssh-blocker ssh-blocker /run/ssh-blocker.fifo
    - (rsyslog starts here)

    When the iptables rules are loaded:
    - Create the whitelist and blacklist ipsets with timeout support (do not
      fail if the set has been created before):
        ipset -exist create ssh-whitelist hash:ip timeout 0
        ipset -exist create ssh-blocklist hash:ip timeout 0
    - Use iptables-restore to apply rules. An example configuration that first
      applies the whitelist, then the blacklist and finally limits connection
      attempts to 10 per minute is shown below this list.
    - Recommended: add your own IP addresses to the ssh-whitelist. For example,
      if your IP is 203.0.113.1:

        ipset -exist add ssh-whitelist 203.0.113.1 timeout 0

      Since the the ipsets are created with no timeout by default, this will be
      permanently saved (well, as long as you do not destroy or flush the sets).

    An example ipset ruleset for SSH:
    -N ssh
    -A INPUT -p tcp --dport 22 -j ssh
    # Apply ssh-blocker whitelist and blacklists
    -A ssh -m set --match-set ssh-whitelist src -j ACCEPT
    -A ssh -m set --match-set ssh-blocklist src -j DROP
    # Whatever you would normally add for limiting SSH connection attempts
    -A ssh -m recent --name ssh --update --seconds 60 --hitcount 10 -j DROP
    -A ssh -m recent --name ssh --set
    -A ssh -j ACCEPT

#### SECURITY
    This program was originally created to reduce syslog spam. It can also be
    used as a replacement for Fail2ban or DenyHosts if you do not need fancy
    features. As with any program that monitors syslog, note that syslog can
    usually be written by everyone. That means that rogue local users can
    insert bogus entries into the syslog. It is as trivial as:

        logger -p auth.notice -t sshd[1337] '...'
    Therefore, use this program with care. Add known good IP addresses to the
    whitelist and do not let untrusted users to your system.

    When the program is run as root, it tightens its capabilities to
    CAP_NET_ADMIN (for ipset) and CAP_SETUID+CAP_SETGID (for changing users).
    Then it changes to the user as specified in the command line arguments. When
    the user has succesfully changed its real, effective and saved uid/gid, it
    will further tighten its privileges to include CAP_NET_ADMIN only. Note that
    the log file is created and/ or opened before changing users.

#### TODO
    - IPv6 is not supported (yet).
    - Host name lookups for log entries are not supported. Set UseDNS to no in
      your sshd configuration.
    - When over IPLIST_LENGTH (currently 512) different IP addresses are shown
      in the logs, no block will be performed as old entries are overwritten.
      This should only be an issue when a botnet is attacking you. With spoofed
      IP addresses, you have different issues.
    - Nicier log source selection.

#### AUTHORS
Written by <a href="https://github.com/kallyas/">Kally</a>
