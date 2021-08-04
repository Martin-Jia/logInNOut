import setuptools

setuptools.setup(
    name='login and logout tool',
    version='0.0.1',
    author='Mingda Jia',
    author_email='martinchia93@outlook.com',
    description=u'a tool for dealing with login and logout',
    url='https://github.com/Martin-Jia/logInNOut',
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    install_requires=[
        'pyjwt',
        'pymongo'
    ]
)