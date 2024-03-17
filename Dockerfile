FROM python:3.12.1-alpine

WORKDIR /fss

COPY ./requirements.txt ./

RUN \
 apk add --no-cache postgresql-libs && \
 apk add --no-cache --virtual .build-deps gcc musl-dev postgresql-dev && \
 apk add --update musl-dev gcc cargo && \
 python3 -m pip install -r requirements.txt --no-cache-dir && \
 apk --purge del .build-deps


RUN pip install --no-cache-dir -r ./requirements.txt

COPY ./app ./

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]