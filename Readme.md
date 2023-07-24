
# Exchatge - a secured message exchanger (server)

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

## The project is currently in `Beta` stage

[The client](https://github.com/vadniks/ExchatgeDesktopClient)

## License

GNU GPLv3 - to keep the source code open

---

Exchatge - a secured realtime message exchanger (desktop client).
Copyright (C) 2023  Vadim Nikolaev (https://github.com/vadniks)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
