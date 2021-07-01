#!bin/sh

# osをlinux、ARCHをamd64(x86_64)にしてbuild
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CC=/usr/local/bin/x86_64-linux-musl-cc go build --ldflags '-linkmode external -extldflags "-static"' -a -v -o main_8080

scp main_8080 you-tube-sns:~/app/

scp -r templates/ you-tube-sns:~/app/
