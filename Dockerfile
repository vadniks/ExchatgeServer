FROM golang:1.20
EXPOSE 8080:8080
RUN apt update && apt -y install libsodium23 libsodium-dev curl
COPY ./src /server/src
COPY ./build/ExchatgeServer /server/build/ExchatgeServer
RUN go build -C /server/src -o /server/build/ExchatgeServer ExchatgeServer
ENTRYPOINT /bin/sleep 5 && /server/build/ExchatgeServer