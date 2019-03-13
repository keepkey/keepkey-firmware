FROM python:3.6-alpine
WORKDIR /kkemu
COPY ./ /kkemu

RUN python -m ensurepip
RUN pip install \
    requests \
    flask \
    pytest

EXPOSE 5000
CMD ["/kkemu/scripts/emulator/bridge.sh"]
