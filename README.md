# Quick start

1. 你可能需要先安装libssl-dev。
```
sudo apt install libssl-dev
```

2. 编译程序。
```
gcc http-server.c -o http-server -lpthread -lssl -lcrypto
```

3. 运行程序。
```
./http-server
```
