# Dockerfile References: https://docs.docker.com/engine/reference/builder/

# Start from golang:1.12-alpine base image
FROM golang:1.12-alpine

# The latest alpine images don't have some tools like (`git` and `bash`).
# Adding git, bash and openssh to the image
RUN apk update && apk upgrade && \
    apk add --no-cache bash git openssh

# Add Maintainer Info
LABEL maintainer="Abish"

# Set the Current Working Directory inside the container
WORKDIR /Kloudone


# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go get  "golang.org/x/crypto/bcrypt"

RUN go get	 "go.mongodb.org/mongo-driver/bson"
RUN go get	 "go.mongodb.org/mongo-driver/mongo"
RUN go get	 "go.mongodb.org/mongo-driver/mongo/options"

RUN go get	 "github.com/google/uuid"
RUN go get	 "github.com/gorilla/mux"
RUN go get   "github.com/AbishSowrirajan/Kloudone/models" 



# Copy the source from the current directory to the Working Directory inside the container
COPY . .


WORKDIR /Kloudone/controller


# Build the Go app
RUN go build -o  main .

# Expose port 8080 to the outside world
EXPOSE 8080

# Run the executable
CMD ["./main"]