FROM scratch

MAINTAINER GoAbout <tech@goabout.com>

ADD redirector /
ADD etc/redirector.yaml /etc/

ENTRYPOINT ["/redirector"]
CMD ["--listen=0.0.0.0:80", "--config=/etc/redirector.yaml", "--log-format=json"]
