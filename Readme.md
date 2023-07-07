
# Exchatge - a secured message exchanger (server)

The purpose of this project is to easily exchange messages using an
encrypted communication channel in the realtime.

Server supports users registration, authentication and authorization. 
Server is just a secured proxy, so the users behind the NAT (network address translation) 
can easily communicate with each other. 
Connection between user and server is end-to-end encrypted and client can verify 
server's identity via digital signature.

## Dependencies

Server is written entirely in Go. 
The following libraries are used: Sodium, Mongo-driver.

## The project is in development stage

[The client](https://github.com/vadniks/ExchatgeDesktopClient)
