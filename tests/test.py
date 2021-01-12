import PythonCSP as pyCSP

# Указать dn сертификата из MY
certificate = 'Тестовый пользователь 2021'
orig = '<Тестовая строка>'

ret = pyCSP.sign(orig.encode('cp1251'), certificate)
res = pyCSP.delSign(ret).decode("cp1251")
print(f'Original = {orig}')
print(f'Unsigned = {res}')
assert orig == res, 'Ошибка при подписании и/или снятии подписи!!!'
