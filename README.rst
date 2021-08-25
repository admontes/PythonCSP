PythonCSP
=========
Пакет реализующий снятие/установку подписи КриптоПро.

Установка на Debian
-------------------
* Установить КриптоПро CSP и пакет lsb-cprocsp-devel из дистрибутива КриптоПро CSP (https://cryptopro.ru/downloads), например так:

.. code-block:: shell

    /linux-amd64_deb/install.sh    
    find /linux-amd64_deb/ -type f -name "lsb-cprocsp-devel*" -exec dpkg -i "{}" \

* Установить данный пакет используя pip 

.. code-block:: shell

    pip install git+https://github.com/admontes/PythonCSP
     
Описание функций пакета
-----------------------
* Функция *sign* подписывает сообщение. Принимает 2 параметра (сообщение бинарного тип и dn сертификата из хранилища MY). Возвращает подписанное сообщение бинарного типа.
* Функция *get_content* возращает поле content из структуры подписанного сообщения формата ASN.1. Принимает параметр бинарного типа с сообщением ASN.1 и возращает бинарный тип.
* В случае какой либо ошибки пакет вернет исключение RuntimeError с указанием места в котором оно возникло и код ошибки Крипто-Про.
     
Примеры использования
---------------------
.. code-block:: python

    import PythonCSP as pyCSP

    # Указать dn сертификата из MY
    certificate = 'Тестовый пользователь 2021'
    orig = '<Тестовая строка>'

    ret = pyCSP.sign(orig.encode('cp1251'), certificate)
    res = pyCSP.get_content(ret).decode("cp1251")
    print(f'Original = {orig}')
    print(f'Unsigned = {res}')
    assert orig == res, 'Ошибка при подписании и/или снятии подписи!!!'
