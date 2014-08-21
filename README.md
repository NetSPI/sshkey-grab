sshkey-grab
===========

This script uses a bug in ssh-agent that allows it to pull the last key added to the agent.  This may allow the ability to recover a key that has been removed from ssh-agent via ssh-add -t, -d, or -D, provided that the ssh-agent was not terminated and a new key has not been added since the previous one was removed.  This bug has been reported and may be fixed in newer versions of OpenSSH, which will cause this tool to break.

### Requirements

- grabagentmem.sh requries root access and gdb on the target machine to work properly
- parse_mem.py requires the pyasn1 python module to be installed


### Usage

1. Copy grabagentmem.sh to the target machine.  
2. Run grabagentmem.sh on the target machine as root. This will create a memory dump of the stack for each ssh-agent process running on this box.  They will be named /tmp/SSHagent-$PID.stack by default.  
3. Copy the stack traces to the machine that has parse_mem.py installed
4. run parse_mem.py [stack file] \[key output\] (Example: ./parse_mem.py /tmp/SSHagent-17019.stack /tmp/key)
5. Test to see if extracted key file works by using ssh -i [key file] [user]@[machine]


Part of the RSA key creation code is from Thialfihar's Fancy SSH Key Generator: https://github.com/thialfihar/semantic-ssh-key/blob/master/generate_fancy_ssh_key.py
