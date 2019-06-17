make
if [[ $? != 0 ]]
then
    exit $?
fi

git status
read -p "Are you want to push all those files ? [y/n]" answer
if [[ $answer == "y" ]]
then
    git add -A
    git commit
    git push
fi
