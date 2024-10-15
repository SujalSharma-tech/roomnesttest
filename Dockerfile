FROM php:8.0-apache
RUN apt-get update && apt-get install -y zip unzip
WORKDIR /var/www/html
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
RUN docker-php-ext-install  mysqli
RUN composer require firebase/php-jwt
COPY . /var/www/html
COPY index.php index.php
COPY listing-controller.php listing-controller.php
COPY user-controller.php user-controller.php
COPY database.php database.php
EXPOSE 80
