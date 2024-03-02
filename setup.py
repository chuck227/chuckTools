from setuptools import setup, Extension
setup(
    ext_modules=[
        Extension(name='chuckTools.win.processInjection', sources=['chuckTools\\win\\processInjection.c'])
    ]
)