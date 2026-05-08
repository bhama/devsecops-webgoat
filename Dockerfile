# We need JDK as some of the lessons needs to be able to compile Java code
FROM docker.io/eclipse-temurin:25-jdk-noble
LABEL name="WebGoat: A deliberately insecure Web Application"
LABEL maintainer="WebGoat team"

RUN \
  useradd -ms /bin/bash webgoat && \
  chgrp -R 0 /home/webgoat && \
  chmod -R g=u /home/webgoat

USER webgoat
