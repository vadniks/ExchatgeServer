FROM golang:1.20
EXPOSE 8080:8080
COPY ./src /server/src
COPY ./build/ExchatgeServer /server/build/ExchatgeServer
RUN apt update && apt install libsodium23 libsodium-dev
RUN go build -C /server/src -o /server/build/ExchatgeServer ExchatgeServer
ENTRYPOINT /bin/sleep 5 && /server/build/ExchatgeServer