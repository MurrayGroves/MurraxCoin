FROM python:3.8

RUN apt install git
RUN git clone 'https://github.com/MurrayGroves/MurraxCoin.git'

RUN mkdir /data
RUN mkdir /data/Accounts
RUN ln -s /data MurraxCoin/Node

RUN pip install -r MurraxCoin/requirements.txt
WORKDIR MurraxCoin/Node
ENTRYPOINT python3 node.py
