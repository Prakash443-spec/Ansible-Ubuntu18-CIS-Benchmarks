# Update repos
sudo apt-get update

# Upgrade existing packages to latest
sudo apt-get upgrade

# harden SSH - grab the Octopus project variable SSH_PORT
sudo cp /etc/ssh/sshd_config /etc/ssh/backup.sshd_config
SSH_PORT=$(get_octopusvariable "SSH_PORT")
sudo cat > /etc/ssh/sshd_config <<EOL
Port $SSH_PORT
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
macs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
SyslogFacility AUTH
ClientAliveCountMax 2
Compression no
LogLevel VERBOSE
MaxAuthTries 2
MaxSessions 2
LoginGraceTime 30
PermitRootLogin no
StrictModes yes
PubkeyAuthentication yes
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
UseDNS no
MaxStartups 2
EOL

# Install fail2ban
sudo apt-get install fail2ban

# Create new user with sudo rights
newAdminUser=$(get_octopusvariable "AdminUser")
sudo adduser $newAdminUser
sudo usermod -aG sudo $newAdminUser
su - $newAdminUser

# Disable root login
sudo passwd -l root
