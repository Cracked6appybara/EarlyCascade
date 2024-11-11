# Early Cascade Injection

Thanks to Guido Miggelenbrink from Outflanks blog post about this new injection technique. [Early Cascade Injection](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/).

Since I am still quite new to maldev I thought it would be a fun and smart idea to have a go at writing this injection technique out.
I had also seen Cracked5pider try this as well, which I have some bits from their code, and that had helped me get an overall understand
of how I should go about writing this. So big thanks to [Cracked5pider](https://github.com/Cracked5pider/earlycascade-injection) as well.
___

## Things to improve

- [ ] Dynamically get the offsets to both `g_ShimsEnabled` and `g_pfnSE_DllLoaded` Pointers.
- [ ] Store both payloads in other ways. I.e Resources.
