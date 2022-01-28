FROM ethereum/client-go:v1.9.25

ARG NETWORKID
ARG CHAINID
ENV NETWORKID=${NETWORKID}

ADD geth.password /root/geth.password
ADD genesis.json  /root/genesis.json
ADD geth-config.toml /root/geth-config.toml
# change chainId
RUN sed -i -e "s/\"chainId\": 1337/\"chainId\": ${CHAINID}/" /root/genesis.json
ADD privatekey  /root/privatekey
ADD run.sh  /run.sh

RUN mkdir -p /root/backup
RUN /usr/local/bin/geth --datadir /root/.ethereum init /root/genesis.json
RUN /usr/local/bin/geth account import /root/privatekey --password /root/geth.password

EXPOSE 8545 8546 30303

ENTRYPOINT ["/run.sh"]
