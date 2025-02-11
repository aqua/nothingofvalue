FROM golang:latest as builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . ./
RUN ls -l
RUN go build -o main main/main.go
COPY main /app/main
CMD ["/app/main"]
