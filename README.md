sshkey-grab
===========

This script uses a bug in ssh-agent that allows it to pull the last key added to the agent.  This may allow the ability to recover a key that has been removed from ssh-agent via ssh-add -t, -d, or -D provided that ssh-agent was not terminated and a new key has not been added since the previous one was removed.  This bug has been reported and may be fixed in newer versions, breaking this tool.

Part of the RSA key creation code is from Thialfihar's Fancy SSH Key Generator: https://github.com/thialfihar/semantic-ssh-key/blob/master/generate_fancy_ssh_key.py
