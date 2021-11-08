FROM authexec/reactive-base:latest

COPY . .
RUN pip install . \
    && rm -rf *
