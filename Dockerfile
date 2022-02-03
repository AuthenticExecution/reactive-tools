FROM authexec/reactive-base:latest

COPY . .
RUN python -m pip install . \
    && rm -rf *
