FROM php:8.2-apache

# MySQLに繋ぐための拡張だけ入れる
RUN docker-php-ext-install mysqli

COPY index.php /var/www/html/index.php
