# Многопоточный кеширующий прокси

<p align="center">
   <a href="https://github.com/ptrvsrg/cache-proxy/graphs/contributors">
        <img alt="GitHub contributors" src="https://img.shields.io/github/contributors/ptrvsrg/cache-proxy?label=Contributors&labelColor=222222&color=77D4FC"/>
   </a>
   <a href="https://github.com/ptrvsrg/cache-proxy/forks">
        <img alt="GitHub forks" src="https://img.shields.io/github/forks/ptrvsrg/cache-proxy?label=Forks&labelColor=222222&color=77D4FC"/>
   </a>
   <a href="https://github.com/ptrvsrg/cache-proxy/stargazers">
        <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/ptrvsrg/cache-proxy?label=Stars&labelColor=222222&color=77D4FC"/>
   </a>
   <a href="https://github.com/ptrvsrg/cache-proxy/issues">
        <img alt="GitHub issues" src="https://img.shields.io/github/issues/ptrvsrg/cache-proxy?label=Issues&labelColor=222222&color=77D4FC"/>
   </a>
   <a href="https://github.com/ptrvsrg/cache-proxy/pulls">
        <img alt="GitHub pull requests" src="https://img.shields.io/github/issues-pr/ptrvsrg/cache-proxy?label=Pull%20Requests&labelColor=222222&color=77D4FC"/>
   </a>
</p>

## Установка и настройка

### Вручную

1. Убедитесь, что у вас установлен Make и GCC;
2. Клонируйте репозиторий на свою локальную машину;
3. Соберите программу при помощи команды:

    ```shell
    make build
    ```

4. Установите переменные среды:

   `CACHE_PROXY_LOG_LEVEL=<ALL|TRACE|DEBUG|INFO|WARNING|ERROR|FATAL|OFF>` - уровень логгирования

   `CACHE_PROXY_THREAD_POOL_SIZE=<int>` - количество обработчиков запросов клиентов

   `CACHE_PROXY_CACHE_EXPIRED_TIME_MS=<int>` - время жизни записей в кеше в миллисекундах

5. Запустите приложение:

    ```shell
   make run PORT=<int>
   ```
   
    или

    ```shell
   ./build/cache-proxy <int>
   ```

### Docker

1. Убедитесь, что у вас установлен Docker;
2. Запустите контейнер с помощью команды:

    ```shell
    sudo docker run \
    -d \
    -e CACHE_PROXY_LOG_LEVEL=<ALL|TRACE|DEBUG|INFO|WARNING|ERROR|FATAL|OFF> \
    -e CACHE_PROXY_THREAD_POOL_SIZE=<int> \
    -e CACHE_PROXY_CACHE_EXPIRED_TIME_MS=<int> \
    -p <int>:8080 \
    --name <string> \
    ptrvsrg/cache-proxy:latest
    ```

## Вклад в проект

Если вы хотите внести свой вклад в проект, вы можете следовать этим шагам:

1. Создайте форк этого репозитория.
2. Внесите необходимые изменения.
3. Создайте pull request, описывая ваши изменения.