
# Exchatge - a secured message exchanger (server)

```
_______ _     _ _______ _     _ _______ _______  ______ _______
|______  \___/  |       |_____| |_____|    |    |  ____ |______
|______ _/   \_ |_____  |     | |     |    |    |_____| |______
```

The purpose of this project is to easily exchange messages
via binary protocol using an encrypted communication channel
in the realtime.

Server supports users registration, authentication and authorization. 
Server is just a secured proxy, so the users behind the NAT (network address translation) 
can easily communicate with each other. 
Connection between user and server is end-to-end encrypted and client can verify 
server's identity via digital signature.

## `TODO`
* Add messages queues for users to store messages in them while users are offline to allow them fetch messages later

## Dependencies

Server is written entirely in Go. 
The following libraries are used: 
* [Sodium](https://github.com/jamesruan/sodium), 
* [Mongo-driver](https://pkg.go.dev/go.mongodb.org/mongo-driver).

## The project is currently in `Beta`

[Desktop Linux client](https://github.com/vadniks/ExchatgeDesktopClient) \
[Android client](https://github.com/vadniks/ExchatgeAndroidClient)

## Build

Firstly, the LibSodium library and pkg-config are needed to be installed, example for Arch/Manjaro:
```shell
sudo pacman -S libsodium pkgconf
```
Secondly, the project dependencies are needed to be installed, and then, 
the actual build can be performed:
```shell
# should be executed from the repository's root directory
(cd src; go get)
(cd src/crypto; go test) # run crypto tests
go build -C src -o "$(pwd)/build/ExchatgeServer" ExchatgeServer
```

## Deploy

Just run `docker-compose up --build --abort-on-container-exit` from the root directory of this repository. 
Ensure that you have `docker` & `docker-compose` programs installed. Build is 
performed automatically while creating the container.

## Documentation

`TODO`
