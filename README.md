# rinvalidate

Native software validator for the current RinOS v3 RIN, RLL (library RIN),
and NDRV (driver) formats. It checks the ABI, flags, section/table layout,
relocation and symbol metadata, architecture limits, and the RDS1 trusted RSA
signature envelope without importing the Python toolchain.

```text
rinvalidate --kind executable --arch x86_64 --trust-key public.der app.rin
rinvalidate --kind library --trust-key public.der lib.rll
rinvalidate --kind driver --trust-key public.der device.drv
```

`--allow-unsigned` is available for build-stage images and must not be used for
release validation.
