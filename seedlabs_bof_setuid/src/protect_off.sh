#!/bin/dash

# A simple bash script to turn off ASLR and symlink to zsh

sudo sysctl -w kernel.randomize_va_space=0
echo "Address Space Randomisation turned off!"

sudo ln -sf /bin/zsh /bin/sh
echo "/bin/sh symlinked to zsh"
