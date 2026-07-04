FROM php:8.2-apache

# MySQL接続用の拡張 + 診断ツール(ps/top などの procps)
RUN apt-get update \
    && apt-get install -y --no-install-recommends procps \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install mysqli

COPY index.php /var/www/html/index.php
