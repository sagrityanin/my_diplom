# Полная версия проекта находится в репозитарии

git@github.com:sagrityanin/graduate_work.git

![Диаграмма проекта](https://github.com/sagrityanin/graduate_work/blob/main/arch/005_uml_c2.png?raw=true)

## В наш проект входят следующие API

1. [Captcha](https://pycinema.ru/captcha/api/v1)
2. [Recaptcha](https://pycinema.ru/recaptcha/api/v1)
3. [API для пользователей](https://pycinema.ru/auth/api/v1/)
4. [API для управления подпиками для пользователей](https://pycinema.ru/subscriptions/api/openapi)
5. [API для оплаты](https://pycinema.ru)
6. [API для админов](https://pycinema.ru:8443/admin/api/v1/)

### URL для пользователей
1. [Подписки пользователя](https://pycinema.ru/index.html)

### Инструменты для мониторинга
- [Interaction bus](http://pycinema.ru:15672/#/)
- [kibana](http://pycinema.ru:5601)


## Биллинг: общая концепция

![Диаграмма сервиса по спринту 10](https://github.com/sagrityanin/graduate_work/blob/main/arch/005_uml_c3.png?raw=true)

## Работа с платежными шлюзами/аггрегаторами

- External payments: используем API и платежный виджет cloudpayments.ru (ничто не мешает переключиться на любой другой)
- Внешняя интеграция: API-вызов генерации платежнего виджета на базе json-параметров (pay) + API-вызов для приема callback (paid)
- Внутренняя интеграция:
  - принимаем сообщения на шину (rabbitmq) из Client Admin Panel для базового набора вызовов (минимальный перечень: выставить счет на оплату, аннулировать счет на оплату, оформить подписку, вернуть деньги) и (через задачи celery в рамках State Updater) транслируем в API External payments
  - читаем актуальные состояния напрямую из State Storage, меняем **состояния счетов** только через State Updater

## Хранилище состояний

- РСУБД (postgres) со всей информацией - от видов подписок до счетов и состояния по ним

## Машина состояния 

- Реализует модель состояния счетов в РСУБД (цепочка событий по состоянию счета)
- Обновляет модель по consumed-сообщениям из rabbitmq (отдельный consumer-процесс)
- Запускает one-time и scheduled celery tasks, необходимые для реализации модели состояний
- Обновляет модель по результатам работы celery-задач с API External Payment

## Админка

- Subscription price setter: настройка видов подписок менеджерами
- Базовые функции для менеджеров: создать подписку, изменить подписку - прямой работой со State Storage

## Клиентское API

- Пользовательские функции: подписаться, отписаться, оплатить, показать активные подписки
- Работа на прямую со State Storate для получения данных + вызовы State Updater через Interaction Bus при необходимости работы по использованию External Payment

# Напоминанием о продлении
Этой задачей занимается процесс reminder.py в контейнере CRON