FROM golang:1.20
EXPOSE 8080:8080
RUN apt update && apt -y install libsodium23 libsodium-dev curl
COPY ./src /server/src
RUN mkdir /server/build
RUN go build -C /server/src -o /server/build/ExchatgeServer ExchatgeServer
COPY options.txt /server/build/options.txt
ENTRYPOINT /bin/sleep 10 && /server/build/ExchatgeServer