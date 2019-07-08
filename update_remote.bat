git subtree push --prefix output origin master

REM In case of emmergency:
REM # Ensure we are in src
REM git checkout src
REM # Creates chaos branch
REM git subtree split --prefix output -b chaos
REM # Push chaos onto origin/master
REM git push --force origin chaos:master
REM # Deletes chaos
REM git branch -D chaos