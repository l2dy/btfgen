# btfgen

```bash
btfgen -r https://repo.openeuler.org/openEuler-20.03-LTS/debuginfo/x86_64/Packages/
```

## Limitations

- On distributions based on CentOS 7, the minimum version supported is `3.10.0-957`.
- The mainline Linux kernel added `DEBUG_INFO_BTF` config in v5.2, but BTF type information can be generated for older kernels as well. https://github.com/torvalds/linux/commit/e83b9f55448afce3fe1abcd1d10db9584f8042a6
