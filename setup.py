from distutils.core import setup, Extension

PythonCSP = Extension(
    name='PythonCSP',
    sources=['PythonCSP/pythoncsp.c'],
    include_dirs=[
        '/opt/cprocsp/include',
        '/opt/cprocsp/include/cpcsp',
        '/opt/cprocsp/include/pki',
    ],
    define_macros=[
        ('UNIX', '1'),
        ('HAVE_LIMITS_H', '1'),
        ('HAVE_STDINT_H', '1'),
        ('SIZEOF_VOID_P', '8'),
    ],
    extra_link_args=[
        '-L/opt/cprocsp/lib/amd64',
        '-lcapi20',
        '-lcapi10',
        '-lrdrsup',
    ]
)


def main():
    setup(name="PythonCSP",
          version="0.1",
          description="Python interface for the Crypto Pro function",
          author="Nickolay Kravchenko",
          author_email="nikolay.kravchenko@gmail.com",
          ext_modules=[PythonCSP])


if __name__ == "__main__":
    main()
