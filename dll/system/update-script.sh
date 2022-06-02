#!/bin/bash
wget -q -O /usr/bin/yow "https://notabug.org/sakai/tetbot/raw/main/serv-updater.sh" && chmod +x /usr/bin/yow
screen -S updss yow
