fso - fast [link] shortener
===========================

fso is a fast implementation of a link shortener. you can configure your links like so in a `config.fso` file like so:

```
@     :  https://safin.dev
test  :  https://google.com
```

then, build with:

```
make prod
```

and run with:
```
./fso
```

todo:
- [x] multithreading
- [x] hot-reload config file
- [ ] fix broken fd errors

developing:

you can run `make dev` to build a development release with debugging symbols. note that the `prod` goal will apply the `O2` flag to gcc, while `dev` will not.

limitations:
- only works on linux due to use of linux-specific syscalls
