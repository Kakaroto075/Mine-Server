#!/bin/bash
cd /workspaces/Mine-Server
git add .
git commit -m "Backup automático $(date '+%d/%m/%Y %H:%M:%S')"
git push
