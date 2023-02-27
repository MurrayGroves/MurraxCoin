FROM python:3.8

WORKDIR /MurraxCoin
ADD node.py .
ADD bootstrapServer.py .
ADD requirements.txt .

# Allow /data to be either a mounted volume, or exist only within the container for a non-persistent ledger.
RUN mkdir /data
RUN mkdir /data/Accounts
RUN ln -s /data/ data

RUN pip install -r requirements.txt
ENTRYPOINT python3 -u node.py