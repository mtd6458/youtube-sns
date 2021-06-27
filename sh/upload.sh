#!bin/sh

# osをlinux、ARCHをamd64(x86_64)にしてbuild
GOOS=linux GOARCH=amd64 go build -o main_8080

scp main_8080 you-tube-sns:~/app/

scp -r templates/ you-tube-sns:~/app/
